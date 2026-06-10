"""
commands/faq_content.py — Conteúdo estático do FAQ interativo (/faq).

Cada item: id -> (rótulo do botão, corpo HTML). O bot monta um teclado inline
com um botão por tópico (callback_data = "faq:<id>").
"""

FAQ: dict[str, tuple[str, str]] = {
    "score": (
        "How scoring works",
        "<b>[ CTI Relevance Score ]</b>\n"
        "Each report is scored 0–100 from concrete and contextual signals:\n"
        "• Monitored asset mentioned (+40, strongest signal)\n"
        "• Threat category (malware, exploitation, breach, TTPs…)\n"
        "• CVE mentioned (+10) and highest CVSS cited (+20/+30)\n"
        "• Regional relevance (BR/LATAM)\n"
        "• Trusted source boost (capped)\n"
        "High-volume low-value topics (e.g. routine Linux kernel notices) get a "
        "penalty. Only reports at or above the minimum score are delivered.",
    ),
    "alert": (
        "CTI alert anatomy",
        "<b>[ CTI Alert Card ]</b>\n"
        "• Header: severity (🔴🟠🟡🟢 by score) + source type\n"
        "• 🚨 Title (threat layers only)\n"
        "• Metadata: source, date, monitored assets, CWE, threats, "
        "targeted sectors, countries\n"
        "• MITRE ATT&amp;CK techniques (AI-mapped)\n"
        "• Related CVEs\n"
        "• Executive Summary + Impact &amp; Mitigation (AI)\n"
        "• Indicators of Compromise (IPs, domains, hashes)\n"
        "• 🔗 Source and 📎 cited references\n"
        "A second <b>Sentinel Hunting</b> card with KQL follows when applicable.",
    ),
    "hunting": (
        "Hunting / Sentinel KQL",
        "<b>[ Sentinel Hunting ]</b>\n"
        "When an alert has IoCs, monitored assets or TTPs, the bot generates a "
        "second card with ready-to-paste <b>KQL</b> queries for Microsoft "
        "Sentinel / Defender XDR:\n"
        "• IoC hunts (IP / domain / hash)\n"
        "• Asset hunts (connections to the vendor's infrastructure)\n"
        "• Technique hunts (one KQL per MITRE ATT&amp;CK technique detected)\n"
        "Queries are template-based, so the syntax is always valid.",
    ),
    "cve": (
        "CVE prioritization",
        "<b>[ CVE Prioritization ]</b>\n"
        "CVEs are collected from the <b>NVD</b> and only alerted when they match "
        "your <b>asset inventory</b> (vendor/product). Risk is computed from:\n"
        "• CVSS (base severity)\n"
        "• EPSS (probability of exploitation)\n"
        "• CISA KEV (known exploited in the wild)\n"
        "Each alert links the official <b>vendor advisory</b>.\n"
        "Use <code>/cve CVE-YYYY-NNNN</code> to look up any CVE on demand.",
    ),
    "commands": (
        "Commands &amp; language",
        "<b>[ Commands ]</b>\n"
        "• <code>/cti</code>, <code>/cves</code> — latest reports\n"
        "• <code>/cve &lt;id&gt;</code> — on-demand CVE lookup\n"
        "• <code>/iniciar</code> — run the pipeline now\n"
        "• <code>/feeds</code> — source health\n"
        "• <code>/stats</code> — metrics dashboard\n"
        "• <code>/patchtuesday</code> — Microsoft Patch Tuesday\n"
        "• <code>/idioma</code> — set alert language (PT/EN)\n"
        "• <code>/status</code>, <code>/recarregar</code>, <code>/ativos</code>\n"
        "In groups, address commands to the bot (e.g. <code>/status@bot</code>) "
        "unless privacy mode is off.",
    ),
    "glossary": (
        "Glossary",
        "<b>[ Glossary ]</b>\n"
        "• <b>IoC</b> — Indicator of Compromise (IP, domain, file hash)\n"
        "• <b>TTP</b> — Tactic/Technique/Procedure (MITRE ATT&amp;CK)\n"
        "• <b>CWE</b> — Common Weakness Enumeration (flaw class)\n"
        "• <b>CVE</b> — Common Vulnerabilities and Exposures (a specific flaw)\n"
        "• <b>CVSS</b> — severity score (0–10)\n"
        "• <b>EPSS</b> — probability a CVE will be exploited\n"
        "• <b>KEV</b> — CISA's Known Exploited Vulnerabilities catalog\n"
        "• <b>PSIRT</b> — a vendor's Product Security Incident Response Team",
    ),
}
