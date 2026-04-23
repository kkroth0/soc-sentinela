"""
cve/aliases.py — Mapeamento de Aliases para Vendors e Produtos.
Baseado nas categorias fornecidas pelo SOC.
Ajuda a mitigar a fragilidade do String Matching direto entre Excel e NVD.
"""

# Mapeia palavras-chave conhecidas (que podem vir do NVD) 
# para os aliases abrangentes que o SOC pode colocar no Excel.
VENDOR_ALIASES: dict[str, list[str]] = {
"amazon": [
        "amazon web services", "aws", "amazon",
        "amazon ec2", "amazon s3", "amazon eks", "amazon rds",
    ],
    "microsoft": [
        "microsoft", "azure", "windows", "entra", "defender",
        "office", "sql server", "exchange", "sharepoint", "teams",
        "iis", "active directory", "hyper-v", "power platform",
        "outlook", "onedrive", "skype",
    ],
    "google": [
        "google cloud platform", "gcp", "google workspace",
        "android", "chrome", "chromium", "google",
    ],
    "oracle": [
        "oracle cloud infrastructure", "oci", "oracle",
        "oracle database", "oracle weblogic", "java se",
    ],
    "ibm": [
        "ibm cloud", "ibm", "db2", "websphere", "qradar", "guardium",
    ],
    "digitalocean": ["digitalocean"],
    "linode": ["linode", "akamai"],

    # ── Virtualization & Private Cloud ────────────────────────────────────────
    "vmware": [
        "vmware", "vsphere", "esxi", "vcenter", "nsx", "vsan",
        "carbon black", "horizon", "aria", "vrealize", "workspace one",
        "vmware tools",
    ],
    "nutanix": ["nutanix", "ahv", "prism"],
    "citrix": ["citrix", "xenserver", "netscaler", "virtual apps", "storefront"],
    "proxmox": ["proxmox", "proxmox server solutions"],

    # ── Operating Systems ─────────────────────────────────────────────────────
    "linux": ["linux kernel", "linux"],
    "redhat": [
        "red hat", "rhel", "centos", "ansible", "jboss", "wildfly",
        "openshift", "keycloak",
    ],
    "canonical": ["ubuntu", "canonical"],
    "debian": ["debian"],
    "rocky": ["rocky linux"],
    "almalinux": ["almalinux"],
    "suse": ["suse", "sles", "opensuse"],
    "apple": [
        "apple", "macos", "ios", "ipados", "safari",
        "xcode", "webkit", "tvos", "watchos",
    ],

    # ── Containers & Orchestration ────────────────────────────────────────────
    "docker": ["docker", "docker desktop", "docker engine"],
    "kubernetes": ["kubernetes", "k8s"],

    # ── Core Internet Infrastructure ──────────────────────────────────────────
    "openssl": ["openssl"],
    "openssh": ["openssh"],
    "mozilla": ["mozilla", "firefox", "thunderbird", "nss"],
    "php": ["php"],
    "exim": ["exim"],
    "postfix": ["postfix"],

    # ── Networking & Perimeter Security ──────────────────────────────────────
    "cisco": [
        "cisco", "cisco ios", "cisco nx-os", "cisco asa",
        "firepower", "meraki", "catalyst", "duo security",
        "webex", "cisco secure",
    ],
    "fortinet": [
        "fortinet", "fortigate", "forticlient", "fortimail",
        "fortiweb", "fortimanager", "fortiadc", "fortiproxy",
        "fortisiem", "fortianalyzer",
    ],
    "paloaltonetworks": [
        "palo alto", "pan-os", "globalprotect", "prisma",
        "cortex", "xsoar", "expedition",
    ],
    "checkpoint": [
        "check point", "quantum", "gaia", "harmony",
        "capsule", "cloudguard",
    ],
    "f5": ["f5", "big-ip", "nginx", "nginx plus"],
    "juniper": ["juniper", "junos", "srx", "juniper networks"],
    "aruba": ["aruba", "clearpass", "edgeconnect", "aruba networks"],
    "zscaler": ["zscaler", "zia", "zpa"],
    "mikrotik": ["mikrotik", "routeros"],
    "ubiquiti": ["ubiquiti", "ui", "unifi", "edgemax", "edgeos"],
    "arista": ["arista", "eos"],
    "forcepoint": ["forcepoint"],
    "barracuda": ["barracuda", "barracuda email security"],
    "sonicwall": ["sonicwall", "sonicos"],

    # ── Endpoint / EDR ────────────────────────────────────────────────────────
    "crowdstrike": ["crowdstrike", "falcon"],
    "sentinelone": ["sentinelone", "singularity"],
    "trendmicro": ["trend micro", "apex one", "vision one", "deep security"],
    "sophos": ["sophos", "intercept x", "xg firewall", "sophos firewall"],
    "broadcom": ["broadcom", "symantec", "sep", "symantec endpoint protection"],
    "trellix": ["trellix", "mcafee", "fireeye", "hx series"],
    "bitdefender": ["bitdefender", "gravityzone"],
    "kaspersky": [
        "kaspersky", "kaspersky endpoint security", "kaspersky security center",
    ],

    # ── IAM / PAM ─────────────────────────────────────────────────────────────
    "okta": ["okta", "auth0"],
    "cyberark": ["cyberark", "privileged access manager", "conjur"],
    "beyondtrust": ["beyondtrust", "powerbroker"],
    "delinea": ["delinea", "thycotic", "secret server", "privilege manager"],
    "hashicorp": ["hashicorp", "vault", "boundary", "terraform", "consul", "nomad"],
    "pingidentity": ["ping identity", "pingone", "pingfederate"],
    "onelogin": ["onelogin"],
    "thales": ["thales", "safenet", "ciphertrust"],
    "sailpoint": ["sailpoint", "identityiq", "identitynow"],

    # ── Vulnerability Management ──────────────────────────────────────────────
    "tenable": ["tenable", "nessus", "tenable.sc", "tenable.io", "tenable.ot"],
    "rapid7": ["rapid7", "metasploit", "insightvm", "nexpose"],
    "qualys": ["qualys", "vmdr", "qualys cloud platform"],

    # ── Databases & Middleware ────────────────────────────────────────────────
    "mysql": ["mysql", "mysql server"],
    "postgresql": ["postgresql", "postgres"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elastic": [
        "elasticsearch", "elastic stack", "elk", "kibana",
        "logstash", "beats", "elastic",
    ],
    "mariadb": ["mariadb"],
    "sap": ["sap", "hana", "sap netweaver", "sap business one"],
    "apache": [
        "apache httpd", "apache struts", "log4j", "apache tomcat",
        "apache kafka", "apache solr", "apache spark",
        "apache commons", "apache xml",
    ],
    "cassandra": ["cassandra", "apache cassandra"],

    # ── DevOps & CI/CD ────────────────────────────────────────────────────────
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab", "gitlab ce", "gitlab ee"],
    "github": ["github", "github enterprise", "github actions"],
    "atlassian": [
        "atlassian", "jira", "confluence", "bitbucket",
        "bamboo", "crowd",
    ],
    "puppet": ["puppet"],
    "chef": ["chef"],

    # ── Observability & SIEM ──────────────────────────────────────────────────
    "splunk": ["splunk", "splunk enterprise", "splunk soar"],
    "zabbix": ["zabbix"],
    "grafana": ["grafana", "grafana labs"],
    "prometheus": ["prometheus"],
    "datadog": ["datadog"],
    "dynatrace": ["dynatrace"],

    # ── Backup & Storage ──────────────────────────────────────────────────────
    "veeam": ["veeam", "veeam backup"],
    "veritas": ["veritas", "netbackup", "backup exec"],
    "commvault": ["commvault"],
    "cohesity": ["cohesity"],
    "rubrik": ["rubrik"],
    "dell": [
        "dell", "poweredge", "powerstore", "unity",
        "data domain", "isilon", "avamar",
    ],
    "netapp": ["netapp", "ontap", "snapcenter"],
    "purestorage": ["pure storage", "flasharray", "flashblade"],
    "hpe": ["hpe", "nimble", "alletra", "proliant", "ilo"],
    "synology": ["synology", "dsm", "diskstation manager"],
    "qnap": ["qnap", "qts", "quts hero"],
    "western_digital": ["western digital", "mycloud", "wd", "my cloud"],

    # ── IT Management / ITSM ──────────────────────────────────────────────────
    "ivanti": [
        "ivanti", "pulse secure", "connect secure", "neurons",
        "avalanche", "ivanti endpoint manager", "mobileiron",
    ],
    "solarwinds": ["solarwinds", "orion", "solarwinds platform"],
    "zohocorp": [
        "manageengine", "admanager", "servicedesk",
        "adaudit plus", "desktop central", "endpoint central",
        "pam360", "password manager pro",
    ],

    # ── Alta Recorrência em CVEs Recentes ─────────────────────────────────────
    "progress": ["progress software", "moveit", "whatsup gold", "telerik"],
    "papercut": ["papercut", "papercut ng", "papercut mf"],
}

def get_aliases_for_vendor(nvd_vendor: str) -> list[str]:
    """Retorna a lista de aliases para um vendor do NVD. Retorna o próprio vendor na lista como base."""
    nvd_vendor = nvd_vendor.lower()
    # BUG-02 Fix: Usar list() para criar uma cópia defensiva e não mutar o dicionário global
    aliases = list(VENDOR_ALIASES.get(nvd_vendor, []))
    # Sempre inclui o próprio nome original lido do NVD p/ garantir match
    if nvd_vendor not in aliases:
        aliases.append(nvd_vendor)
    return aliases
