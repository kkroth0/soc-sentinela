"""
config.py — Centraliza TODAS as variáveis de ambiente.
Nenhum outro módulo deve chamar os.getenv() diretamente.
Caminhos de arquivo são sempre resolvidos como absolutos.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── Diretório-base do projeto ────────────────────────────────────────
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))

# ─── APIs ─────────────────────────────────────────────────────────────
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")


# ─── Microsoft Teams ──────────────────────────────────────────────────
TEAMS_WEBHOOK_URL: str = os.getenv("TEAMS_WEBHOOK_URL", "")
TEAMS_WEBHOOK_CVE: str = os.getenv("TEAMS_WEBHOOK_CVE", "")
TEAMS_WEBHOOK_CTI: str = os.getenv("TEAMS_WEBHOOK_CTI", "")
TEAMS_WEBHOOK_SECRET: str = os.getenv("TEAMS_WEBHOOK_SECRET", "")
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID_CVE: str = os.getenv("TELEGRAM_CHAT_ID_CVE", "")
TELEGRAM_CHAT_ID_CTI: str = os.getenv("TELEGRAM_CHAT_ID_CTI", "")

# ─── Microsoft Graph API (SharePoint) ────────────────────────────────
GRAPH_TENANT_ID: str = os.getenv("GRAPH_TENANT_ID", "")
GRAPH_CLIENT_ID: str = os.getenv("GRAPH_CLIENT_ID", "")
GRAPH_CLIENT_SECRET: str = os.getenv("GRAPH_CLIENT_SECRET", "")
SHAREPOINT_SITE_URL: str = os.getenv("SHAREPOINT_SITE_URL", "")
SHAREPOINT_FILE_PATH: str = os.getenv("SHAREPOINT_FILE_PATH", "")

# ─── OneDrive Pessoal (Alternativa ao SharePoint Corporativo) ───────
ONEDRIVE_DIRECT_URL: str = os.getenv("ONEDRIVE_DIRECT_URL", "")

# ─── E-mail / Power Automate ─────────────────────────────────────────
EMAIL_FLOW_URL: str = os.getenv("EMAIL_FLOW_URL", "")
SOC_EMAIL: str = os.getenv("SOC_EMAIL", "")

# ─── Thresholds e janelas de tempo ────────────────────────────────────
MIN_CVSS_SCORE: float = float(os.getenv("MIN_CVSS_SCORE", "2.0"))
TIME_WINDOW_MINUTES: int = int(os.getenv("TIME_WINDOW_MINUTES", "5"))
NEWS_TIME_WINDOW_MINUTES: int = int(os.getenv("NEWS_TIME_WINDOW_MINUTES", "60"))
CISA_KEV_CACHE_HOURS: int = int(os.getenv("CISA_KEV_CACHE_HOURS", "24"))
MAX_CVE_AGE_DAYS: int = int(os.getenv("MAX_CVE_AGE_DAYS", "30"))

# ─── Caminhos de arquivo — sempre absolutos ──────────────────────────
BOT_DB_PATH: str = os.path.abspath(
    os.getenv("BOT_DB_PATH", os.path.join(BASE_DIR, "data", "bot_database.db"))
)
ASSETS_CACHE_PATH: str = os.path.abspath(
    os.getenv("ASSETS_CACHE_PATH", os.path.join(BASE_DIR, "data", "clients_assets.xlsx"))
)
VENDOR_ALIASES_PATH: str = os.path.abspath(
    os.path.join(BASE_DIR, "data", "vendor_aliases.json")
)
CTI_CATEGORIES_PATH: str = os.path.abspath(
    os.path.join(BASE_DIR, "data", "cti_categories.json")
)

# ─── Servidor de comandos ────────────────────────────────────────────
COMMAND_PORT: int = int(os.getenv("COMMAND_PORT", "8765"))

# ─── URLs base de APIs externas (não configuráveis via env) ──────────
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"
CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Detecta se é API Free (:fx no final) ou Pro para setar a URL correta
GRAPH_BASE_URL: str = "https://graph.microsoft.com/v1.0"
GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# ─── Prompts de IA ──────────────────────────────────────────────────
PROMPT_CVE_INTEL: str = (
    "Você é um analista de SOC sênior. Sua tarefa é transformar a descrição técnica de uma CVE "
    "em um texto explicativo estruturado em Português (Brasil) para um relatório executivo. "
    "\n\nESTRUTURA DESEJADA:\n"
    "1º Parágrafo: [Fabricante] lançou atualizações para corrigir a vulnerabilidade [CVE_ID] no [Produto], "
    "com pontuação CVSS [Score]. Explique a causa da falha e o impacto direto (ex: elevação de privilégio, RCE).\n"
    "2º Parágrafo: Detalhe o escopo do problema (versões afetadas, sistemas operacionais específicos) "
    "e o que a exploração permite tecnicamente (ex: falsificação de tokens, acesso a arquivos).\n"
    "\nREGRAS:\n"
    "- Mantenha o rigor técnico, mas seja claro e objetivo.\n"
    "- PRESERVE termos técnicos e jargões de cibersegurança no original em Inglês (ex: Race Condition, Buffer Overflow, Bypass, Payload, Heap Spraying, etc).\n"
    "- Responda EXCLUSIVAMENTE em formato JSON: {'description_pt': 'texto_explicativo', 'headline_pt': 'título_curto'}\n"
    "- O 'headline_pt' deve ter no máximo 80 caracteres."
)

PROMPT_NEWS_INTEL: str = (
    "Você é um analista de Cyber Threat Intelligence focado em resumos técnicos rápidos. "
    "Traduza o título e faça um resumo executivo em Português (Brasil) seguindo a REGRA DE 2 PARÁGRAFOS.\n\n"
    "REGRA DE 2 PARÁGRAFOS:\n"
    "Parágrafo 1: Descrição detalhada do que foi descoberto (ameaça, vulnerabilidade, campanha).\n"
    "Parágrafo 2: Impacto e ações recomendadas — quem é afetado e o que deve ser feito (correção, mitigação).\n\n"
    "REGRAS CRÍTICAS:\n"
    "1. Resumo estritamente factual. NÃO invente nomes de grupos, TTPs ou conclusões.\n"
    "2. PROIBIDO frases como 'É importante que...', 'As organizações devem...', ou explicar o que são siglas.\n"
    "3. Responda EXCLUSIVAMENTE em formato JSON: {'title_pt': '...', 'summary_pt': '...'}"
)


def validate_config() -> None:
    """Valida se as configurações críticas estão presentes."""
    # Precisamos da GROQ para inteligência
    if not GROQ_API_KEY:
        raise ValueError("ERRO CRÍTICO: GROQ_API_KEY ausente no .env")

    # Precisamos de pelo menos UM notificador configurado (Teams ou Telegram)
    has_teams = any([TEAMS_WEBHOOK_URL, TEAMS_WEBHOOK_CVE, TEAMS_WEBHOOK_CTI])
    has_telegram = all([TELEGRAM_BOT_TOKEN, any([TELEGRAM_CHAT_ID_CVE, TELEGRAM_CHAT_ID_CTI])])
    
    if not has_teams and not has_telegram:
        raise ValueError("ERRO CRÍTICO: Nenhum canal de notificação configurado (Teams ou Telegram)")
    
    if not TEAMS_WEBHOOK_SECRET:
        from core.logger import get_logger
        get_logger("config").warning("⚠️ TEAMS_WEBHOOK_SECRET não configurado. Servidor de comandos operando em MODO INSEGURO.")
    
    # Validar formato básico das URLs
    for url_name, url in [("Global", TEAMS_WEBHOOK_URL), ("CVE", TEAMS_WEBHOOK_CVE), ("CTI", TEAMS_WEBHOOK_CTI)]:
        if url and not url.startswith("https://"):
            raise ValueError(f"ERRO CRÍTICO: TEAMS_WEBHOOK_{url_name} deve começar com https://")

    # Garante que os diretórios de dados existam
    os.makedirs(os.path.dirname(BOT_DB_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(ASSETS_CACHE_PATH), exist_ok=True)
