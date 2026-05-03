# 🛡️ SOC Sentinel — CTI & Vulnerability Automation

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-hexagonal-orange.svg)
![Status](https://img.shields.io/badge/status-production--ready-green.svg)
![AI](https://img.shields.io/badge/AI-Groq%20Llama--3.3--70B-blueviolet.svg)

O **SOC Sentinel** é um orquestrador avançado de inteligência contra ameaças (CTI) e gerenciamento de vulnerabilidades (CVE). Ele automatiza a descoberta, análise, correlação de ativos e notificação de incidentes, permitindo que analistas de SOC foquem na resposta, não na triagem manual.

---

## 🚀 Funcionalidades Principais

### 🧠 Inteligência Artificial de Elite
- **Análise com Llama-3.3-70B**: Resumos técnicos profissionais e extração automática de IoCs (IPs, Domínios, Hashes) usando a API da Groq.
- **Fallback Adaptativo**: Sistema inteligente que alterna entre modelos (70B, 8B, Mixtral) e ajusta o truncamento de texto para garantir resiliência 100%.

### 🔎 Monitoramento de Ameaças (CTI)
- **Deep Web Scraping**: Utiliza a biblioteca `Scrapling` com Stealth Fetchers para burlar proteções anti-bot (Cloudflare, etc.) e extrair conteúdo técnico profundo.
- **Deduplicação Inteligente**: Filtra notícias repetidas e irrelevantes usando normalização de URLs e hashing.
- **Notificações Ricas**: Alertas visuais no Microsoft Teams (Adaptive Cards) e Telegram (HTML).

### 🛡️ Gestão de Vulnerabilidades (CVE)
- **Ingestão Paralela NVD**: Download massivo de dados da NIST usando Threading controlado por Throttling rigoroso.
- **Vendor Indexing**: Correlação ultra-rápida entre CVEs e Inventário de Ativos (Excel/Cloud) através de indexação por Vendor.
- **Scoring de Risco Real**: Priorização baseada em CVSS, EPSS (Probabilidade de Exploração) e presença no CISA KEV (Exploração Ativa).

---

## 🛠️ Arquitetura Técnica

O projeto segue princípios de **Hexagonal Architecture** e **Clean Code**, garantindo que as fontes de dados e os canais de notificação sejam facilmente substituíveis.

- **Core**: Gerenciamento de banco de dados (SQLite WAL Mode), sessões HTTP com Connection Pooling e logs rotativos.
- **Scrapers**: Motores de raspagem resilientes com camuflagem de headers.
- **Formatters**: Camada de apresentação dedicada para garantir experiência visual premium em todos os dispositivos.
- **Housekeeping**: Rotina automática de limpeza e manutenção de dados.

---

## 📦 Instalação e Uso

1. **Requisitos**:
   - Python 3.10 ou superior.
   - Chaves de API: Groq, NVD (opcional), Telegram Bot Token, Teams Webhook.

2. **Setup**:
   ```bash
   git clone https://github.com/kkroth0/soc-sentinela.git
   cd soc-sentinela
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Execução**:
   ```bash
   python bot.py
   ```

---

## 📊 Estrutura de Logs
O sistema mantém logs profissionais em `logs/sentinel.log` com rotação automática de 10MB, garantindo rastreabilidade total sem esgotar o armazenamento.

---

## ⚖️ Licença
© 2026 Matheus Andrade (@kkroth0). Desenvolvido para operações de SOC de alta performance.
