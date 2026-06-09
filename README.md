# 🛡️ SOC Sentinel — Cyber Threat Intelligence Telegram Bot

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-hexagonal-orange.svg)
![Status](https://img.shields.io/badge/status-production--ready-green.svg)
![AI](https://img.shields.io/badge/AI-Groq%20Llama--3.3--70B-blueviolet.svg)
![Interface](https://img.shields.io/badge/interface-Telegram%20Bot-blue.svg)

O **SOC Sentinel** é um assistente inteligente e orquestrador especializado em **Cyber Threat Intelligence (CTI)** e inteligência contra ameaças corporativas. Integrado diretamente ao **Telegram**, ele automatiza a coleta, triagem, enriquecimento de IoCs e monitoramento contra ativos em tempo real, permitindo que analistas de SOC interajam diretamente com o ecossistema de inteligência via comandos rápidos.

---

## 🚀 Funcionalidades Principais

### 🧠 Inteligência Artificial de Elite (CTI Enriquecido)
- **Análise com Llama-3.3-70B**: Tradução inteligente, resumos executivos profissionais de incidentes e extração automatizada de IoCs (IPs, Domínios, Hashes) via Groq API.
- **Fallback Adaptativo**: Sistema resiliente que alterna entre modelos (70B, 8B, Mixtral) para garantir continuidade das análises.

### 🔎 Monitoramento de Ameaças em Camadas (CTI)
- **Deep Web & Feed Scraping**: Coleta proativa de feeds de inteligência de fornecedores (Fortinet, Cisco, GitLab, Chrome), notícias gerais de segurança (BleepingComputer, HackerNews) e fóruns especializados de pesquisa (SANS, SentinelOne).
- **Stealth Scrapers**: Utiliza `Scrapling` com evasão de anti-bot (Cloudflare, etc.) para extração de textos na íntegra.
- **Deduplicação e Normalização**: Base de dados local (SQLite WAL) que evita o reenvio de alertas redundantes ou repetidos.
- **Notificações HTML Enriquecidas**: Mensagens limpas, estruturadas e com marcações visuais de severidade no Telegram.

### 💬 Interatividade Total via Telegram
- **Comandos On-Demand**: Converse com o bot no Telegram para obter o status da operação, disparar análises manuais ou consultar inteligência acumulada.
- **Segurança de Acesso**: Filtro integrado que autoriza comandos apenas de chats e usuários do SOC pré-configurados no ambiente.

### 🛡️ Gestão e Correlação de Vulnerabilidades
- **Ingestão Paralela NVD & Asset Matching**: Download controlado de dados da NIST correlacionado com o Inventário de Ativos indexado por Vendor/Produto.
- **Score de Risco Real**: Priorização baseada em CVSS, EPSS (probabilidade de exploração) e feeds do CISA KEV (Known Exploited Vulnerabilities).

---

## 🛠️ Arquitetura Técnica

O projeto adota os princípios de **Hexagonal Architecture** (Portas e Adaptadores), permitindo excelente separação de conceitos e facilidade para plugar novas fontes de dados ou ajustar canais de entrega.

- **`core/`**: Infraestrutura centralizada (banco de dados, logging unificado, pooling HTTP e IA Engine).
- **`cti/`**: Coletores, scrappers e motor de scoring de relevância para notícias e campanhas.
- **`cve/`**: Mapeador de ativos, cliente NVD e regras de enriquecimento de risco (EPSS/CISA).
- **`commands/`**: Bot interativo do Telegram com controle de sessão e processamento de comandos.

---

## 💬 Comandos do Telegram

| Comando | Ação |
| --- | --- |
| `/status` | Uptime, modelo de IA, janelas CTI/CVE e estatísticas da base |
| `/iniciar` | Executa manualmente os pipelines CTI **e** CVE |
| `/cti` (`/latest`) | Últimas 10 notícias CTI registradas |
| `/cves` (`/cve`) | Últimas 10 CVEs priorizadas |
| `/ativos` (`/sync`) | Força sincronização do inventário de ativos |
| `/recarregar` | Recarrega categorias CTI e aliases em memória |

> Os cartões de notícia são **adaptáveis por camada**: ameaças (camadas 1–3) exibem a seção *Impacto & Mitigação*; o Radar Regional (camada 4) exibe *Por que importa*. Os pesos de relevância vivem em `data/cti_categories.json` (fonte de verdade única — editável a quente via `/recarregar`).

## 📦 Instalação e Configuração

### Requisitos
- Python 3.10 ou superior.
- Conta e chaves de API: **Groq**, **Telegram Bot Token** e Chat IDs configurados.

### Configuração do Ambiente (`.env`)
Copie o arquivo `.env.example` para `.env` e configure as credenciais necessárias.

```bash
# Telegram Bot
TELEGRAM_BOT_TOKEN="seu_token_aqui"
TELEGRAM_CHAT_ID_CTI="-100xxxxxxxxx"
TELEGRAM_CHAT_ID_CVE="-100xxxxxxxxx"

# IA Engine
GROQ_API_KEY="sua_chave_groq"
```

### Inicialização local
```bash
pip install -r requirements.txt
python bot.py
```

### Rodando via Docker (Recomendado)
```bash
docker-compose up -d --build
```

---

## ⚖️ Licença
© 2026 Matheus Andrade (@kkroth0). Desenvolvido para operações de SOC e CTI de alta performance.
