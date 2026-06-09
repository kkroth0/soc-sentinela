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


# ─── Telegram Bot ─────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID_CVE: str = os.getenv("TELEGRAM_CHAT_ID_CVE", "")
TELEGRAM_CHAT_ID_CTI: str = os.getenv("TELEGRAM_CHAT_ID_CTI", "")

# Lista de IDs de chat (ou usuários) permitidos para executar comandos.
# Exemplo no .env: TELEGRAM_ALLOWED_CHATS="-1001234567,98765432"
_allowed_chats_env = os.getenv("TELEGRAM_ALLOWED_CHATS", "")
TELEGRAM_ALLOWED_CHATS: list[int] = []
if _allowed_chats_env:
    for x in _allowed_chats_env.split(","):
        x_clean = x.strip()
        if x_clean.lstrip('-').isdigit():
            TELEGRAM_ALLOWED_CHATS.append(int(x_clean))

# Adiciona os canais de envio de alertas como permitidos por padrão
for cid in (TELEGRAM_CHAT_ID_CVE, TELEGRAM_CHAT_ID_CTI):
    if cid and cid.lstrip('-').isdigit():
        val = int(cid)
        if val not in TELEGRAM_ALLOWED_CHATS:
            TELEGRAM_ALLOWED_CHATS.append(val)

# ─── Thresholds e janelas de tempo ────────────────────────────────────
MIN_CVSS_SCORE: float = float(os.getenv("MIN_CVSS_SCORE", "2.0"))
TIME_WINDOW_MINUTES: int = int(os.getenv("TIME_WINDOW_MINUTES", "5"))
NEWS_TIME_WINDOW_MINUTES: int = int(os.getenv("NEWS_TIME_WINDOW_MINUTES", "60"))
# Intervalo (min) do agendamento do pipeline CVE. A janela de coleta da NVD é
# sempre >= 24h, então rodar de hora em hora é suficiente e poupa rate-limit.
CVE_SCHEDULE_MINUTES: int = int(os.getenv("CVE_SCHEDULE_MINUTES", "60"))

# Porta do health server HTTP (usada pelo Docker HEALTHCHECK / DO App Platform).
HEALTH_PORT: int = int(os.getenv("COMMAND_PORT", os.getenv("HEALTH_PORT", "8765")))
CISA_KEV_CACHE_HOURS: int = int(os.getenv("CISA_KEV_CACHE_HOURS", "24"))
MAX_CVE_AGE_DAYS: int = int(os.getenv("MAX_CVE_AGE_DAYS", "30"))
MIN_CTI_SCORE: int = int(os.getenv("MIN_CTI_SCORE", "40"))

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
VENDOR_ADVISORIES_PATH: str = os.path.abspath(
    os.getenv("VENDOR_ADVISORIES_PATH", os.path.join(BASE_DIR, "data", "vendor_advisories.json"))
)
CTI_CATEGORIES_PATH: str = os.path.abspath(
    os.path.join(BASE_DIR, "data", "cti_categories.json")
)
CTI_FEEDS_PATH: str = os.path.abspath(
    os.getenv("CTI_FEEDS_PATH", os.path.join(BASE_DIR, "data", "cti_feeds.json"))
)



# ─── URLs base de APIs externas ────────────────────────────────────
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"
CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
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
    "Você é um analista de Cyber Threat Intelligence sênior.\n"
    "Sua missão é gerar um relatório técnico conciso e EXTRAIR TODOS OS IoCs (Hashes, IPs, Domínios).\n\n"
    "ESTRUTURA DO JSON:\n"
    "1. 'title_pt': Título traduzido de forma profissional.\n"
    "2. 'summary_pt': DOIS PARÁGRAFOS separados OBRIGATORIAMENTE por \\n\\n. "
    "O 1º descreve, de forma técnica, O QUE aconteceu (a ameaça, o incidente ou o fato). "
    "O 2º depende do tipo da notícia: se for vulnerabilidade/incidente, traga o IMPACTO e as MEDIDAS DE MITIGAÇÃO; "
    "se for notícia de mercado, regulatória, geopolítica ou regional (sem ameaça técnica direta), traga a RELEVÂNCIA ESTRATÉGICA — por que isso importa para uma operação de SOC/CTI. "
    "NUNCA invente medidas de mitigação para fatos que não são incidentes técnicos.\n"
    "3. 'iocs_pt': Um objeto JSON com as chaves 'IPs', 'Domínios' e 'Hashes'. Extraia categorizadamente todos os IPs, Domínios e Hashes (MD5/SHA) encontrados. "
    "Muitos sites listam isso sob os títulos 'C2 and Infrastructure' ou 'Analyzed files/hashes'. "
    "Extraia TUDO o que for indicador técnico. Se não houver nenhum, escreva 'Nenhum IoC identificado'.\n"
    "4. 'sectors_pt': Array JSON com os SETORES que são ALVO/VÍTIMA da ameaça (ex.: 'Saúde', 'Financeiro', 'Governo', 'Energia', 'Indústria', 'Telecomunicações', 'Varejo', 'Educação', 'Defesa'). "
    "Inclua APENAS setores claramente atacados/visados no texto. Use [] se a notícia não indicar setor-alvo.\n"
    "5. 'countries_pt': Array JSON com os PAÍSES/REGIÕES que são ALVO/VÍTIMA do ataque (ex.: 'Brasil', 'Estados Unidos', 'Ucrânia'). "
    "CRÍTICO: NÃO inclua o país de ORIGEM do atacante (ex.: um grupo APT russo atacando a Ucrânia → o alvo é 'Ucrânia', não 'Rússia'). Use [] se não houver alvo geográfico claro.\n\n"
    "REGRAS CRÍTICAS:\n"
    "• Procure IoCs especialmente no final do texto (seções técnicas).\n"
    "• Preserve termos técnicos em Inglês.\n"
    "• Não invente IoCs; extraia apenas o que está no texto.\n"
    "• Responda APENAS o JSON, sem conversas adicionais."
)


def validate_config() -> None:
    """Valida se as configurações críticas estão presentes."""
    # Precisamos da GROQ para inteligência
    if not GROQ_API_KEY:
        raise ValueError("ERRO CRÍTICO: GROQ_API_KEY ausente no .env")

    # Precisamos do Telegram Bot Token configurado
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("ERRO CRÍTICO: TELEGRAM_BOT_TOKEN ausente no .env")
        
    if not TELEGRAM_CHAT_ID_CTI:
        raise ValueError("ERRO CRÍTICO: TELEGRAM_CHAT_ID_CTI ausente no .env")

    # Garante que os diretórios de dados existam
    os.makedirs(os.path.dirname(BOT_DB_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(ASSETS_CACHE_PATH), exist_ok=True)
