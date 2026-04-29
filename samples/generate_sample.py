import openpyxl

def create_sample_spreadsheet():
    wb = openpyxl.Workbook()
    
    # 1. Sheet Assets (Whitelist)
    ws_assets = wb.active
    ws_assets.title = "Assets"
    
    # Cabeçalho da Whitelist
    ws_assets.append(["Client", "Vendor", "Product", "Aliases"])
    
    # Dados de exemplo Whitelist (Baseado na lista massiva enviada pelo usuário + Enriquecimento de Aliases)
    # Formato: [Client, Vendor, Product, Aliases]
    assets_data = [
        ["Global SOC", "Amazon Web Services", "AWS", "aws, amazon_web_services, ec2, s3, lambda"],
        ["Global SOC", "Microsoft", "Azure", "azure_cloud, microsoft_azure, entra_id"],
        ["Global SOC", "Google", "Cloud Platform", "gcp, google_cloud, compute_engine"],
        ["Global SOC", "Oracle", "Cloud Infrastructure", "oci, oracle_cloud, compute"],
        ["Global SOC", "IBM", "Cloud", "ibm_cloud, softlayer"],
        ["Global SOC", "DigitalOcean", "DigitalOcean", "do_cloud, droplet"],
        ["Global SOC", "Akamai", "Linode", "linode_cloud, akamai_cloud"],
        ["Global SOC", "VMware", "vSphere", "vsphere, esxi, vcenter, horizon"],
        ["Global SOC", "VMware", "ESXi", "esxi, hypervisor, vSphere_ESXi"],
        ["Global SOC", "VMware", "vCenter", "vcenter_server, vCSA"],
        ["Global SOC", "VMware", "NSX", "nsx-t, nsx-v, nsx_data_center"],
        ["Global SOC", "VMware", "vSAN", "vsan_storage"],
        ["Global SOC", "Nutanix", "AHV", "ahv_hypervisor, nutanix_ahv"],
        ["Global SOC", "Nutanix", "Prism", "prism_central, prism_element"],
        ["Global SOC", "Citrix", "XenServer", "xenserver, citrix_hypervisor"],
        ["Global SOC", "Citrix", "NetScaler", "netscaler_adc, citrix_adc, ns_vpx"],
        ["Global SOC", "Citrix", "Virtual Apps", "virtual_apps, xenapp, xendesktop"],
        ["Global SOC", "Proxmox Server Solutions", "Proxmox", "pve, proxmox_ve, proxmox_virtual_environment"],
        ["Global SOC", "Microsoft", "Windows Server 2016", "win_server_2016, windows_server_2016, windows_2016"],
        ["Global SOC", "Microsoft", "Windows Server 2019", "win_server_2019, windows_server_2019, windows_2019"],
        ["Global SOC", "Microsoft", "Windows Server 2022", "win_server_2022, windows_server_2022, windows_2022"],
        ["Global SOC", "Microsoft", "Windows 10", "win10, windows_10, workstation_10"],
        ["Global SOC", "Microsoft", "Windows 11", "win11, windows_11, workstation_11"],
        ["Global SOC", "Red Hat", "Enterprise Linux", "rhel, enterprise_linux, redhat_linux"],
        ["Global SOC", "Canonical", "Ubuntu", "ubuntu_linux, canonical_ubuntu"],
        ["Global SOC", "Debian", "GNU/Linux", "debian_linux, debian_os"],
        ["Global SOC", "CentOS", "CentOS", "centos_linux, centos_os"],
        ["Global SOC", "Rocky Enterprise Software Foundation", "Rocky Linux", "rocky_linux, rl"],
        ["Global SOC", "AlmaLinux", "AlmaLinux", "almalinux_os, almalinux"],
        ["Global SOC", "SUSE", "Linux Enterprise Server", "suse_linux, sles, sle_server"],
        ["Global SOC", "Apple", "macOS", "macos, osx, mac_os_x"],
        ["Global SOC", "Apple", "iOS", "iphone_os, ios_os"],
        ["Global SOC", "Apple", "iPadOS", "ipados_os"],
        ["Global SOC", "Google", "Android Enterprise", "android_os, android_enterprise"],
        ["Global SOC", "Docker", "Engine", "docker_engine, docker_ce, docker_ee"],
        ["Global SOC", "Docker", "Desktop", "docker_desktop"],
        ["Global SOC", "Docker", "Swarm", "docker_swarm"],
        ["Global SOC", "Kubernetes", "Kubernetes", "k8s, k8s_engine, aks, eks, gke"],
        ["Global SOC", "Cisco", "IOS", "cisco_ios, ios_xe, ios_xr"],
        ["Global SOC", "Cisco", "NX-OS", "nx-os, nexus_os"],
        ["Global SOC", "Cisco", "ASA", "adaptive_security_appliance, asa_software"],
        ["Global SOC", "Cisco", "Firepower", "firepower_threat_defense, ftd, fireamp"],
        ["Global SOC", "Cisco", "Meraki", "meraki_dashboard, meraki_os"],
        ["Global SOC", "Cisco", "Catalyst", "catalyst_switch, catalyst_os"],
        ["Global SOC", "Fortinet", "FortiGate", "fortigate_fw, fortios, fortigate_ips"],
        ["Global SOC", "Fortinet", "FortiClient", "forticlient_ems, forticlient_vpn"],
        ["Global SOC", "Fortinet", "FortiMail", "fortimail_gateway, fortimail_os"],
        ["Global SOC", "Fortinet", "FortiWeb", "fortiweb_waf, fortiweb_os"],
        ["Global SOC", "Palo Alto Networks", "PAN-OS", "panos, pan-os, pan_os, palo_alto_os"],
        ["Global SOC", "Palo Alto Networks", "GlobalProtect", "global_protect, gp_vpn"],
        ["Global SOC", "Palo Alto Networks", "Prisma", "prisma_access, prisma_cloud, prisma_sdwan"],
        ["Global SOC", "Check Point", "Quantum", "quantum_gateway, cp_quantum"],
        ["Global SOC", "Check Point", "Gaia", "gaia_os, checkpoint_gaia"],
        ["Global SOC", "Check Point", "Harmony", "harmony_endpoint, harmony_browse"],
        ["Global SOC", "F5 Networks", "BIG-IP", "big-ip, bigip, f5_big-ip, f5_networks"],
        ["Global SOC", "F5 Networks", "NGINX Plus", "nginx_plus, nginx_os"],
        ["Global SOC", "Juniper Networks", "Junos", "junos_os, juniper_junos"],
        ["Global SOC", "Juniper Networks", "SRX", "srx_series, srx_gateway"],
        ["Global SOC", "Aruba Networks", "ClearPass", "clearpass_policy_manager, cppm"],
        ["Global SOC", "Aruba Networks", "EdgeConnect", "edgeconnect_sd-wan, silver_peak"],
        ["Global SOC", "Zscaler", "ZIA", "zia, zscaler_internet_access"],
        ["Global SOC", "Zscaler", "ZPA", "zpa, zscaler_private_access"],
        ["Global SOC", "MikroTik", "RouterOS", "routeros, mikrotik_os"],
        ["Global SOC", "Ubiquiti", "UniFi", "unifi_controller, unifi_os"],
        ["Global SOC", "Ubiquiti", "EdgeMax", "edgemax, edgerouter, edgeswitch"],
        ["Global SOC", "Arista Networks", "Arista", "arista_eos, eos"],
        ["Global SOC", "HPE", "Networking", "hpe_networking, hpe_switch"],
        ["Global SOC", "Forcepoint", "Forcepoint", "forcepoint_web, forcepoint_ngfw"],
        ["Global SOC", "Barracuda Networks", "Barracuda", "barracuda_waf, barracuda_ngf"],
        ["Global SOC", "SonicWall", "SonicWall", "sonicos, sonicwall_firewall"],
        ["Global SOC", "CrowdStrike", "Falcon", "falcon_sensor, crowdstrike_falcon"],
        ["Global SOC", "SentinelOne", "Singularity", "singularity_endpoint, s1_agent"],
        ["Global SOC", "Trend Micro", "Apex One", "apex_one, officescan"],
        ["Global SOC", "Trend Micro", "Vision One", "vision_one, xdr"],
        ["Global SOC", "Sophos", "Intercept X", "intercept_x, sophos_endpoint"],
        ["Global SOC", "Sophos", "XG Firewall", "xg_firewall, sfos, sophos_xg"],
        ["Global SOC", "Microsoft", "Defender for Endpoint", "mde, defender_atp, windows_defender"],
        ["Global SOC", "Broadcom", "Symantec Endpoint Protection", "sep, symantec_endpoint, sep_cloud"],
        ["Global SOC", "Trellix", "McAfee", "mcafee_ens, trellix_ens, epo"],
        ["Global SOC", "Trellix", "FireEye", "fireeye_nx, fireeye_hx, fireeye_os"],
        ["Global SOC", "Bitdefender", "GravityZone", "gravityzone, bitdefender_gz"],
        ["Global SOC", "Kaspersky", "Endpoint Security", "kes, kaspersky_endpoint, kes_linux"],
        ["Global SOC", "Carbon Black", "VMware Carbon Black", "carbon_black, cb_response, cb_protection"],
        ["Global SOC", "Okta", "Identity Cloud", "okta_identity, okta_sso"],
        ["Global SOC", "Microsoft", "Entra ID", "entra_id, azure_ad, msal"],
        ["Global SOC", "Microsoft", "Azure AD", "azure_active_directory, aad"],
        ["Global SOC", "CyberArk", "Privileged Access Manager", "pam, cyberark_pam, pas"],
        ["Global SOC", "BeyondTrust", "PAM", "beyondtrust_pam, password_safe"],
        ["Global SOC", "HashiCorp", "Vault", "hashicorp_vault, vault_server"],
        ["Global SOC", "HashiCorp", "Boundary", "hashicorp_boundary"],
        ["Global SOC", "Ping Identity", "Ping", "ping_federate, ping_id"],
        ["Global SOC", "OneLogin", "OneLogin", "onelogin_sso"],
        ["Global SOC", "Cisco", "Duo Security", "duo, duo_security, duo_auth"],
        ["Global SOC", "Thales", "SafeNet", "safenet, thales_hsm"],
        ["Global SOC", "SailPoint", "SailPoint", "sailpoint_iiq, identityiq"],
        ["Global SOC", "Microsoft", "SQL Server", "mssql, sql_server, mssql_server"],
        ["Global SOC", "Oracle", "Database", "oracle_db, rdbms"],
        ["Global SOC", "Oracle", "MySQL", "mysql, mysql_server"],
        ["Global SOC", "PostgreSQL", "PostgreSQL", "postgres, psql"],
        ["Global SOC", "MongoDB", "MongoDB", "mongo, mongod"],
        ["Global SOC", "Redis", "Redis", "redis_server, redis_stack"],
        ["Global SOC", "Elastic", "Elasticsearch", "elasticsearch, elastic_search"],
        ["Global SOC", "MariaDB", "MariaDB", "mariadb_server"],
        ["Global SOC", "IBM", "DB2", "ibm_db2, db2_luw"],
        ["Global SOC", "SAP", "HANA", "sap_hana, hana_database"],
        ["Global SOC", "Apache", "Cassandra", "cassandra_db"],
        ["Global SOC", "SQLite", "SQLite", "sqlite_db"],
        ["Global SOC", "Apache", "HTTP Server", "httpd, apache, apache_http_server"],
        ["Global SOC", "Nginx", "Nginx", "nginx_server, nginx_engine"],
        ["Global SOC", "Microsoft", "Internet Information Services", "iis, iis_server"],
        ["Global SOC", "Apache", "Tomcat", "tomcat_server, apache_tomcat"],
        ["Global SOC", "Red Hat", "JBoss", "jboss_eap, jboss_as"],
        ["Global SOC", "Red Hat", "WildFly", "wildfly_as"],
        ["Global SOC", "Oracle", "WebLogic", "weblogic_server"],
        ["Global SOC", "Jenkins", "Jenkins", "jenkins_ci, jenkins_server"],
        ["Global SOC", "GitLab", "GitLab", "gitlab_ce, gitlab_ee, gitlab_runner"],
        ["Global SOC", "GitHub", "Enterprise", "github_enterprise, ghe"],
        ["Global SOC", "GitHub", "Actions", "github_actions"],
        ["Global SOC", "Atlassian", "Jira", "jira_software, jira_core, jira_service_desk"],
        ["Global SOC", "Atlassian", "Confluence", "confluence_server, confluence_datacenter"],
        ["Global SOC", "Atlassian", "Bitbucket", "bitbucket_server, bitbucket_dc"],
        ["Global SOC", "Red Hat", "Ansible", "ansible_tower, ansible_automation_platform"],
        ["Global SOC", "HashiCorp", "Terraform", "terraform_cli, terraform_cloud"],
        ["Global SOC", "Puppet", "Puppet", "puppet_server, puppet_enterprise"],
        ["Global SOC", "Chef", "Chef", "chef_infra, chef_server"],
        ["Global SOC", "Splunk", "Enterprise", "splunk_enterprise, splunk_server"],
        ["Global SOC", "Splunk", "SOAR", "splunk_soar, phantom"],
        ["Global SOC", "Elastic", "Elastic Stack", "elastic_stack, elk, logstash, kibana"],
        ["Global SOC", "Zabbix", "Zabbix", "zabbix_server, zabbix_agent"],
        ["Global SOC", "Grafana", "Grafana", "grafana_server"],
        ["Global SOC", "Prometheus", "Prometheus", "prometheus_server"],
        ["Global SOC", "Microsoft", "Exchange", "exchange_server, ms_exchange, owa"],
        ["Global SOC", "Microsoft", "SharePoint", "sharepoint_server, sharepoint_online, sps"],
        ["Global SOC", "Microsoft", "Teams", "microsoft_teams, msteams"],
        ["Global SOC", "Google", "Workspace", "google_workspace, gsuite, drive, gmail"],
        ["Global SOC", "Slack", "Slack", "slack_app, slack_desktop"],
        ["Global SOC", "Zoom", "Zoom", "zoom_client, zoom_meeting"],
        ["Global SOC", "Salesforce", "Salesforce", "salesforce_crm, sfdc"],
        ["Global SOC", "Veeam", "Backup & Replication", "veeam, vbr, veeam_backup"],
        ["Global SOC", "Veritas", "NetBackup", "netbackup, nbu"],
        ["Global SOC", "Veritas", "Backup Exec", "backup_exec, be"],
        ["Global SOC", "Commvault", "Commvault", "commvault_complete, metallic"],
        ["Global SOC", "Cohesity", "Cohesity", "cohesity_data_platform, helios"],
        ["Global SOC", "Rubrik", "Rubrik", "rubrik_polaris, rsc"],
        ["Global SOC", "Dell", "PowerEdge", "poweredge_server, idrac"],
        ["Global SOC", "Dell", "PowerStore", "powerstore_os"],
        ["Global SOC", "Dell", "Unity", "unity_oe, unity_storage"],
        ["Global SOC", "Dell", "Data Domain", "data_domain, ddboost, ddos"],
        ["Global SOC", "NetApp", "ONTAP", "ontap_os, fas, aff"],
        ["Global SOC", "Pure Storage", "Pure Storage", "purity_os, flasharray, flashblade"],
        ["Global SOC", "HPE", "Nimble", "nimble_os, nimble_storage"],
        ["Global SOC", "HPE", "Alletra", "alletra_storage"],
        ["Global SOC", "Synology", "DSM", "dsm_os, diskstation"],
        ["Global SOC", "QNAP", "QTS", "qts_os, qnap_os"],
        ["Global SOC", "Ivanti", "VPN", "ivanti_connect_secure, pulse_secure"],
        ["Global SOC", "Ivanti", "Patch Management", "ivanti_patch_manager, shavlik"],
        ["Global SOC", "SolarWinds", "Orion", "orion_platform, solarwinds_orion"],
        ["Global SOC", "ManageEngine", "ADManager", "admanager_plus, manageengine"],
        ["Global SOC", "ManageEngine", "ServiceDesk", "servicedesk_plus, me_servicedesk"]
    ]
    
    for row in assets_data:
        ws_assets.append(row)
        
    # 2. Sheet Blacklist
    ws_blacklist = wb.create_sheet("Blacklist")
    
    # Cabeçalho da Blacklist
    ws_blacklist.append(["Vendor", "Product", "Aliases", "Motivo"])
    
    # Dados de exemplo Blacklist
    blacklist_data = [
        ["Adobe",               "Flash Player",                    "flash",                                        "Vendor bloqueado"],
        ["Microsoft",           "Internet Explorer",               "ie11",                                         "Vendor bloqueado"], 
        ["Mansurahamed",        "WP Plugins (various)",            "mansurahamed",                                 "Vendor bloqueado"],
        ["Lubus",               "Swift Framework / Themes",        "lubus, swift-framework",                       "Vendor bloqueado"],
        ["Scottpaterson",       "WP Plugins (various)",            "scottpaterson",                                "Vendor bloqueado"],
        ["Tareqhasan / weDevs", "WP Project Manager, WooCommerce Extensions", "tareqhasan, wedevs",               "Vendor bloqueado"],
        ["Micahblu",            "WP Plugins (various)",            "micahblu",                                     "Vendor bloqueado"],
        ["Buynowdepot",         "Buy Now Plus",                    "buynowdepot, buy-now-plus",                    "Vendor bloqueado"],
        ["Widgilabs",           "WP Plugins (various)",            "widgilabs",                                    "Vendor bloqueado"],
        ["Webandprint",         "WP Plugins (various)",            "webandprint",                                  "Vendor bloqueado"],
        ["Litespeedtech",       "LiteSpeed Cache for WordPress",   "litespeed, litespeed-cache, lscwp",            "Vendor bloqueado"],
        ["Hmplugin",            "Happy Addons for Elementor",      "hmplugin, happy-addons, happyaddons",          "Vendor bloqueado"],
        ["Mondula",             "Multi Step Form",                 "mondula, multi-step-form",                     "Vendor bloqueado"],
        ["Greenshiftwp",        "Greenshift Blocks & Page Builder","greenshiftwp, greenshift",                     "Vendor bloqueado"],
        ["Progress Planner",    "Progress Planner",                "progress-planner",                             "Vendor bloqueado"],
        ["Wpmudev",             "Smush, Hummingbird, Hustle, Defender", "wpmudev, smush, hummingbird, hustle, defender", "Vendor bloqueado"],
        ["Zaytech",             "Smart Online Order for Clover",   "zaytech, smart-online-order",                  "Vendor bloqueado"],
        ["Renzojohnson",        "WP Plugins (various)",            "renzojohnson",                                 "Vendor bloqueado"],
        ["Sunshinephotocart",   "Sunshine Photo Cart",             "sunshinephotocart, sunshine-photo-cart",       "Vendor bloqueado"],
        ["Wpmanageninja",       "FluentForms, FluentCRM, FluentBooking", "wpmanageninja, fluentforms, fluentcrm, fluentbooking", "Vendor bloqueado"],
        ["Templately",          "Templately Template Library",     "templately",                                   "Vendor bloqueado"],
        ["Kraftplugins",        "Mega Elements for Elementor",     "kraftplugins, mega-elements",                  "Vendor bloqueado"],
        ["Androidbubbles",      "WP Plugins (various)",            "androidbubbles",                               "Vendor bloqueado"],
        ["Code-Atlantic",       "Popup Maker, User Switching",     "code-atlantic, popup-maker, user-switching",   "Vendor bloqueado"],
        ["Depicter",            "Depicter Slider & Popup",         "depicter",                                     "Vendor bloqueado"],
        ["Ninjateam",           "WP Plugins (various)",            "ninjateam",                                    "Vendor bloqueado"],
        ["Rainbow-Link",        "WP Plugins (various)",            "rainbow-link",                                 "Vendor bloqueado"],
        ["Wcproducttable",      "WooCommerce Product Table",       "wcproducttable, wc-product-table",             "Vendor bloqueado"],
        ["Averta",              "Phlox Theme, Master Slider",      "averta, phlox, master-slider",                 "Vendor bloqueado"]
    ]
    
    for row in blacklist_data:
        ws_blacklist.append(row)
        
    # Auto-adjust columns width
    for ws in [ws_assets, ws_blacklist]:
        for col in ws.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = (max_length + 2)
            ws.column_dimensions[column].width = adjusted_width

    wb.save("data/clients_assets.xlsx")
    print("Planilha template gerada com sucesso em data/clients_assets.xlsx!")

if __name__ == "__main__":
    create_sample_spreadsheet()
