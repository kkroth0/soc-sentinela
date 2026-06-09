# 🛡️ SOC Sentinel

![Python](https://img.shields.io/badge/Python-3.12-blue.svg)
![AI](https://img.shields.io/badge/AI-Groq%20Llama--3.3--70B-blueviolet.svg)
![Interface](https://img.shields.io/badge/Interface-Telegram-blue.svg)
![Deploy](https://img.shields.io/badge/Deploy-Docker-2496ED.svg)

Bot de **Cyber Threat Intelligence (CTI)** e **gestão de vulnerabilidades (CVE)** para SOC, integrado ao **Telegram**. Coleta feeds de ameaças e CVEs, enriquece com IA, e envia alertas prontos para o analista — automaticamente, 24/7.

---

## O que ele faz

- **Coleta CTI** de 32 feeds RSS (PSIRT de vendors + notícias de segurança) e raspa o conteúdo completo de cada matéria.
- **Enriquece cada análise** com: resumo via IA, IoCs (IPs/domínios/hashes), CWE, **setores e países atacados**, **TTPs (MITRE ATT&CK)** e CVEs relacionadas.
- **Monitora CVEs** do NVD, correlaciona com seu **inventário de ativos** (por vendor/produto) e prioriza por **CVSS + EPSS + CISA KEV**.
- **Linka o advisory oficial** do vendor em cada alerta de CVE (editável em `data/vendor_advisories.json`).
- **Responde comandos** no Telegram (status, disparo manual, consultas).
- **Deduplica** tudo em SQLite para não repetir alerta.

---

## 🧰 O que está sendo utilizado

| Camada | Tecnologia |
| --- | --- |
| **Linguagem** | Python 3.12 |
| **Interface** | Telegram Bot API (long polling via `requests`) |
| **IA** | **Groq** — Llama 3.3 70B (tradução, resumo executivo, extração de IoCs) |
| **Fontes CTI** | RSS via `feedparser` (Fortinet PSIRT, Cisco PSIRT, MSRC, CISA, Ubuntu, Debian, Red Hat, BleepingComputer, HackerNews, SANS…) |
| **Web scraping** | `Scrapling` — Fetcher rápido (curl_cffi) + **StealthyFetcher** (Chromium, evasão de anti-bot/Cloudflare) |
| **Fontes CVE** | **NVD** (NIST) + **EPSS** (prob. de exploração) + **CISA KEV** |
| **Enriquecimento** | MITRE ATT&CK (TTPs), CWE, setores/países, advisories de vendor |
| **Inventário** | Planilha Excel via `openpyxl` |
| **Persistência** | SQLite (modo WAL) |
| **Agendamento** | `APScheduler` |
| **Config** | `python-dotenv` (`.env`) + arquivos JSON em `data/` |
| **Deploy** | Docker + Docker Compose |

### Estrutura
- **`core/`** — banco, logging, HTTP, engine de IA, health check
- **`cti/`** — feeds RSS, scraping, scoring e enriquecimento de notícias
- **`cve/`** — cliente NVD, asset matching, score de risco e advisories
- **`commands/`** — bot interativo do Telegram

---

## 💬 Comandos do Telegram

| Comando | Ação |
| --- | --- |
| `/status` | Uptime, modelo de IA, janelas CTI/CVE e estatísticas |
| `/iniciar` | Executa manualmente os pipelines CTI **e** CVE |
| `/cti` (`/latest`) | Últimas 10 notícias CTI |
| `/cves` (`/cve`) | Últimas 10 CVEs priorizadas |
| `/ativos` (`/sync`) | Sincroniza o inventário de ativos |
| `/recarregar` | Recarrega feeds, aliases, advisories e categorias (a quente) |

> Em **grupos/canais**, comandos precisam do `@` (ex.: `/status@seu_bot`) ou do privacy mode desligado no @BotFather.

---

## 🚀 Como rodar

### 1. Configurar o `.env`
Copie `.env.example` para `.env` e preencha:
```bash
TELEGRAM_BOT_TOKEN="..."
TELEGRAM_CHAT_ID_CTI="-100..."
TELEGRAM_ALLOWED_CHATS="..."
NVD_API_KEY="..."
GROQ_API_KEY="..."
```

### 2. Subir com Docker (recomendado)
```bash
docker compose up -d --build
docker compose logs -f
```

### 3. Ou rodar localmente
```bash
pip install -r requirements.txt
python bot.py
```

> Para alertas de CVE, coloque seu inventário em `data/clients_assets.xlsx`.
> Health check disponível em `http://localhost:8765/health`.

---

## ⚖️ Licença
© 2026 Matheus Andrade ([@kkroth0](https://github.com/kkroth0)). Desenvolvido para operações de SOC e CTI.
