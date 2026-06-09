"""
core/constants.py — Constantes globais compartilhadas no projeto.
"""

# Mapeamento de palavras-chaves encontradas em descrições ou textos de notícias
# para suas respectivas tags de Ameaça (Threats).
KEYWORD_THREATS = {
    "ransomware": "Ransomware",
    "trojan": "Trojan",
    "infostealer": "Infostealer",
    "stealer": "Infostealer",
    "wiper": "Wiper",
    "botnet": "Botnet",
    "spyware": "Spyware",
    "rootkit": "Rootkit",
    "backdoor": "Backdoor",
    "phishing": "Phishing",
    "apt": "Grupo APT",
    "zero-day": "Zero-Day",
    "0-day": "Zero-Day",
    "exploit": "Exploitation"
}

# Setores-alvo: rótulo (PT, exibido) -> palavras-chave (PT/EN) que o indicam.
# Casamento por limite de palavra (ver cti.enrichment) para evitar falsos
# positivos com termos curtos.
TARGET_SECTORS = {
    "Saúde": ("healthcare", "hospital", "hospitals", "health system", "medical", "saúde", "hospitalar"),
    "Financeiro": ("bank", "banks", "banking", "financial", "finance", "fintech", "banco", "bancário", "financeiro"),
    "Governo": ("government", "governmental", "ministry", "public sector", "governo", "governamental", "setor público"),
    "Energia": ("energy", "power grid", "electric", "oil and gas", "utility", "utilities", "energia", "elétrica", "petróleo"),
    "Educação": ("education", "university", "universities", "school", "academic", "educação", "universidade", "escola"),
    "Indústria": ("manufacturing", "industrial", "factory", "ics", "ot security", "indústria", "industrial", "fábrica", "manufatura"),
    "Varejo": ("retail", "e-commerce", "ecommerce", "varejo", "comércio eletrônico"),
    "Telecomunicações": ("telecom", "telecommunications", "telco", "telecomunicações", "operadora"),
    "Tecnologia": ("technology sector", "software vendor", "saas", "cloud provider", "tecnologia", "provedor de nuvem"),
    "Transporte": ("transportation", "aviation", "airline", "airport", "logistics", "maritime", "transporte", "aviação", "logística", "portuário"),
    "Defesa": ("defense", "defence", "military", "armed forces", "defesa", "militar", "forças armadas"),
    "Infraestrutura Crítica": ("critical infrastructure", "infraestrutura crítica"),
    "Jurídico": ("law firm", "legal sector", "jurídico", "escritório de advocacia"),
    "Seguros": ("insurance", "insurer", "seguros", "seguradora"),
    "Mídia": ("media outlet", "news organization", "broadcaster", "veículo de mídia", "imprensa"),
}

# Países/regiões: rótulo (PT, exibido) -> palavras-chave/gentílicos (PT/EN).
TARGET_COUNTRIES = {
    "Estados Unidos": ("united states", "u.s.", "usa", "american", "estados unidos", "norte-americano"),
    "Brasil": ("brazil", "brazilian", "brasil", "brasileiro", "brasileira"),
    "Rússia": ("russia", "russian", "rússia", "russo"),
    "China": ("china", "chinese", "chinês", "chinesa"),
    "Ucrânia": ("ukraine", "ukrainian", "ucrânia", "ucraniano"),
    "Irã": ("iran", "iranian", "irã", "iraniano"),
    "Coreia do Norte": ("north korea", "north korean", "dprk", "coreia do norte", "norte-coreano"),
    "Coreia do Sul": ("south korea", "south korean", "coreia do sul", "sul-coreano"),
    "Israel": ("israel", "israeli", "israelense"),
    "Índia": ("india", "indian", "índia", "indiano"),
    "Reino Unido": ("united kingdom", "u.k.", "british", "britain", "reino unido", "britânico"),
    "Alemanha": ("germany", "german", "alemanha", "alemão", "alemã"),
    "França": ("france", "french", "frança", "francês", "francesa"),
    "Japão": ("japan", "japanese", "japão", "japonês", "japonesa"),
    "México": ("mexico", "mexican", "méxico", "mexicano"),
    "Argentina": ("argentina", "argentine", "argentinian", "argentino"),
    "Colômbia": ("colombia", "colombian", "colômbia", "colombiano"),
    "Chile": ("chile", "chilean", "chileno"),
    "Espanha": ("spain", "spanish", "espanha", "espanhol", "espanhola"),
    "Canadá": ("canada", "canadian", "canadá", "canadense"),
    "Austrália": ("australia", "australian", "austrália", "australiano"),
}

# Técnicas MITRE ATT&CK: rótulo "Txxxx — Nome" -> palavras-chave (PT/EN) que a
# indicam. Curado para os termos que mais aparecem em notícias de CTI; o
# casamento é por limite de palavra (ver cti.enrichment) para evitar ruído.
ATTACK_TTPS = {
    "T1566 — Phishing": ("phishing", "phishing email", "campanha de phishing"),
    "T1566.001 — Spearphishing Attachment": ("spearphishing", "spear phishing", "spear-phishing", "malicious attachment", "anexo malicioso"),
    "T1190 — Exploit Public-Facing Application": ("public-facing application", "remote code execution", "rce", "execução remota de código", "exploração de vulnerabilidade"),
    "T1204 — User Execution": ("malicious macro", "macro-enabled", "malicious document", "macro maliciosa", "documento malicioso"),
    "T1486 — Data Encrypted for Impact": ("ransomware", "encrypts files", "file-encrypting", "criptografa arquivos"),
    "T1485 — Data Destruction": ("wiper", "data wiping", "destructive malware", "malware destrutivo"),
    "T1003 — OS Credential Dumping": ("credential dumping", "mimikatz", "lsass", "dump de credenciais"),
    "T1555 — Credentials from Password Stores": ("stolen credentials", "credential theft", "roubo de credenciais", "credenciais roubadas"),
    "T1110 — Brute Force": ("brute force", "brute-force", "password spraying", "credential stuffing", "força bruta"),
    "T1059.001 — PowerShell": ("powershell",),
    "T1053 — Scheduled Task/Job": ("scheduled task", "tarefa agendada"),
    "T1055 — Process Injection": ("process injection", "dll injection", "code injection", "injeção de processo", "injeção de código"),
    "T1068 — Exploitation for Privilege Escalation": ("privilege escalation", "elevation of privilege", "escalonamento de privilégio", "elevação de privilégio"),
    "T1547 — Boot or Logon Autostart Execution": ("autostart", "registry run key", "chave de execução"),
    "T1021.001 — Remote Desktop Protocol": ("rdp", "remote desktop", "área de trabalho remota"),
    "T1021 — Remote Services": ("lateral movement", "movimentação lateral", "movimento lateral"),
    "T1071 — Application Layer Protocol (C2)": ("command and control", "command-and-control", "c2 server", "c2 infrastructure", "servidor c2"),
    "T1041 — Exfiltration Over C2 Channel": ("data exfiltration", "exfiltrate", "exfiltrated", "exfiltração de dados"),
    "T1195 — Supply Chain Compromise": ("supply chain", "supply-chain", "cadeia de suprimentos"),
    "T1505.003 — Web Shell": ("web shell", "webshell"),
    "T1078 — Valid Accounts": ("valid accounts", "compromised account", "conta comprometida", "contas válidas"),
    "T1498 — Network Denial of Service": ("ddos", "denial of service", "dos attack", "negação de serviço"),
    "T1496 — Resource Hijacking": ("cryptojacking", "cryptomining", "cryptocurrency miner", "coinminer", "criptomineração"),
    "T1027 — Obfuscated Files or Information": ("obfuscation", "obfuscated", "ofuscação", "ofuscado"),
}
