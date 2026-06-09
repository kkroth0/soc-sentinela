"""
cti/hunting.py — Geração de queries de Threat Hunting para Microsoft Sentinel.

A partir dos IoCs, ativos afetados e TTPs (MITRE ATT&CK) de uma notícia CTI,
monta queries KQL prontas para colar no Microsoft Sentinel / Defender XDR
(Advanced Hunting). Abordagem determinística por templates: o KQL é sempre
sintaticamente válido e apenas "semeado" com os indicadores reais.
"""
import re
from typing import Any

from core.models import StandardCTINews

# ─── Extração de indicadores ─────────────────────────────────────────
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Extensões/sufixos que o regex de domínio captura por engano.
_DOMAIN_NOISE = {"exe", "dll", "js", "py", "ps1", "bat", "zip", "rar", "doc",
                 "docx", "pdf", "png", "jpg", "gif", "html", "php", "json", "xml"}


def _flatten(iocs: Any) -> str:
    """Reduz o campo de IoCs (dict categorizado ou string) a texto plano."""
    if isinstance(iocs, dict):
        parts: list[str] = []
        for v in iocs.values():
            if isinstance(v, (list, tuple)):
                parts.extend(str(x) for x in v)
            elif isinstance(v, dict):
                parts.extend(str(x) for x in v.values())
            else:
                parts.append(str(v))
        text = " ".join(parts)
    else:
        text = str(iocs or "")
    # Remove "defang" comum (1.2.3[.]4, hxxp, evil(.)com)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")


def _parse_iocs(iocs: Any) -> tuple[list[str], list[str], list[str]]:
    """Retorna (ips, domínios, hashes) únicos extraídos dos IoCs."""
    text = _flatten(iocs)
    ips = list(dict.fromkeys(_IP_RE.findall(text)))
    hashes = list(dict.fromkeys(_HASH_RE.findall(text)))

    domains: list[str] = []
    for d in _DOMAIN_RE.findall(text):
        d = d.lower().strip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld in _DOMAIN_NOISE or _IP_RE.fullmatch(d):
            continue
        if d not in domains:
            domains.append(d)
    return ips, domains, hashes


def _kql_list(items: list[str]) -> str:
    """Formata uma lista Python como literal dynamic([...]) do KQL."""
    return "dynamic([" + ", ".join(f'"{i}"' for i in items) + "])"


# ─── Domínios oficiais dos vendors monitorados (para hunts por ativo) ─
_VENDOR_DOMAINS = {
    "microsoft": "microsoft.com", "azure": "azure.com", "office": "office.com",
    "cisco": "cisco.com", "fortinet": "fortinet.com", "sap": "sap.com",
    "servicenow": "service-now.com", "dell": "dell.com", "vmware": "vmware.com",
    "oracle": "oracle.com", "adobe": "adobe.com", "siemens": "siemens.com",
    "trendmicro": "trendmicro.com", "cloudflare": "cloudflare.com",
    "cyberark": "cyberark.com", "netskope": "netskope.com", "akamai": "akamai.com",
    "nokia": "nokia.com", "abb": "abb.com",
}


# ─── Templates de hunt por técnica MITRE ATT&CK ──────────────────────
_TTP_HUNTS: dict[str, tuple[str, str]] = {
    "T1190": ("Exploração de aplicação exposta (conexões de entrada anômalas)",
              "DeviceNetworkEvents\n"
              "| where ActionType == \"InboundConnectionAccepted\"\n"
              "| summarize Hits=count() by RemoteIP, LocalPort, DeviceName, bin(Timestamp, 1h)\n"
              "| where Hits > 100\n"
              "| order by Hits desc"),
    "T1078": ("Uso de contas válidas a partir de locais incomuns",
              "SigninLogs\n"
              "| where ResultType == 0\n"
              "| summarize Logins=count(), Cidades=make_set(tostring(LocationDetails.city)) "
              "by UserPrincipalName, bin(TimeGenerated, 1d)\n"
              "| where array_length(Cidades) > 2"),
    "T1110": ("Força bruta / password spraying",
              "SigninLogs\n"
              "| where ResultType in (50126, 50053, 50055)\n"
              "| summarize Falhas=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)\n"
              "| where Falhas > 20\n"
              "| order by Falhas desc"),
    "T1059.001": ("Execução suspeita de PowerShell",
                  "DeviceProcessEvents\n"
                  "| where FileName =~ \"powershell.exe\"\n"
                  "| where ProcessCommandLine has_any (\"-enc\", \"-EncodedCommand\", "
                  "\"DownloadString\", \"IEX\", \"FromBase64String\")\n"
                  "| project Timestamp, DeviceName, AccountName, ProcessCommandLine"),
    "T1003": ("Possível dump de credenciais (LSASS/Mimikatz)",
              "DeviceProcessEvents\n"
              "| where ProcessCommandLine has_any (\"lsass\", \"sekurlsa\", \"mimikatz\", \"comsvcs.dll\")\n"
              "| project Timestamp, DeviceName, AccountName, ProcessCommandLine"),
    "T1486": ("Atividade de ransomware (renomeação em massa de arquivos)",
              "DeviceFileEvents\n"
              "| where ActionType == \"FileRenamed\"\n"
              "| where FileName matches regex @\"\\.(locked|encrypted|crypt|enc|[a-z0-9]{6,8})$\"\n"
              "| summarize Arquivos=count() by DeviceName, bin(Timestamp, 1h)\n"
              "| where Arquivos > 50"),
    "T1566": ("Phishing entregue",
              "EmailEvents\n"
              "| where DeliveryAction == \"Delivered\"\n"
              "| where ThreatTypes has_any (\"Phish\", \"Malware\")\n"
              "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject"),
    "T1021.001": ("Movimentação lateral via RDP",
                  "DeviceLogonEvents\n"
                  "| where LogonType == \"RemoteInteractive\"\n"
                  "| summarize Sessoes=count() by AccountName, DeviceName, RemoteIP, bin(Timestamp, 1h)\n"
                  "| order by Sessoes desc"),
    "T1071": ("Possível canal de C2 (beaconing)",
              "DeviceNetworkEvents\n"
              "| where isnotempty(RemoteUrl)\n"
              "| summarize Conns=count(), Bytes=sum(SentBytes) by DeviceName, RemoteUrl, bin(Timestamp, 1h)\n"
              "| where Conns > 50 and Bytes > 1000000\n"
              "| order by Conns desc"),
    "T1041": ("Exfiltração de dados (grandes volumes de saída)",
              "DeviceNetworkEvents\n"
              "| summarize TotalEnviado=sum(SentBytes) by DeviceName, RemoteIP, bin(Timestamp, 1h)\n"
              "| where TotalEnviado > 50000000\n"
              "| order by TotalEnviado desc"),
    "T1567": ("Exfiltração via serviço web",
              "DeviceNetworkEvents\n"
              "| where RemoteUrl has_any (\"pastebin\", \"anonfiles\", \"mega.nz\", \"transfer.sh\", \"file.io\")\n"
              "| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"),
}


def build_sentinel_hunts(news: StandardCTINews, limit: int = 6) -> list[dict[str, str]]:
    """Gera a lista de hunts KQL (title + kql) para a notícia."""
    hunts: list[dict[str, str]] = []
    ips, domains, hashes = _parse_iocs(news.iocs)

    # 1) Hunts dirigidos por IoC (mais acionáveis)
    if ips:
        hunts.append({
            "title": "IOC — Conexões para IPs maliciosos",
            "kql": (f"let iocIPs = {_kql_list(ips[:20])};\n"
                    "DeviceNetworkEvents\n"
                    "| where RemoteIP in (iocIPs)\n"
                    "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl\n"
                    "| order by Timestamp desc"),
        })
    if domains:
        hunts.append({
            "title": "IOC — Resolução/acesso a domínios maliciosos",
            "kql": (f"let iocDomains = {_kql_list(domains[:20])};\n"
                    "DeviceNetworkEvents\n"
                    "| where RemoteUrl has_any (iocDomains)\n"
                    "| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName\n"
                    "| order by Timestamp desc"),
        })
    if hashes:
        hunts.append({
            "title": "IOC — Hashes de arquivos maliciosos",
            "kql": (f"let iocHashes = {_kql_list(hashes[:20])};\n"
                    "union DeviceFileEvents, DeviceProcessEvents\n"
                    "| where SHA256 in (iocHashes) or SHA1 in (iocHashes) or MD5 in (iocHashes)\n"
                    "| project Timestamp, DeviceName, FileName, SHA256, InitiatingProcessFileName"),
        })

    # 2) Hunt por ativo monitorado (conexões à infra do vendor)
    seen_vendors: set[str] = set()
    for asset in news.matched_assets:
        dom = _VENDOR_DOMAINS.get(str(asset).strip().lower())
        if dom and dom not in seen_vendors:
            seen_vendors.add(dom)
            hunts.append({
                "title": f"Ativo — Conexões à infraestrutura {asset}",
                "kql": ("DeviceNetworkEvents\n"
                        f"| where RemoteUrl has \"{dom}\"\n"
                        "| summarize Conexoes=count() by DeviceName, InitiatingProcessFileName, AccountName\n"
                        "| order by Conexoes desc"),
            })

    # 3) Hunts por técnica MITRE ATT&CK detectada
    seen_tids: set[str] = set()
    for ttp in news.ttps:
        m = _TID_RE.search(ttp)
        if not m:
            continue
        tid = m.group(0)
        tpl = _TTP_HUNTS.get(tid) or _TTP_HUNTS.get(tid.split(".")[0])
        if tpl and tid not in seen_tids:
            seen_tids.add(tid)
            title, kql = tpl
            hunts.append({"title": f"{tid} — {title}", "kql": kql})

    return hunts[:limit]
