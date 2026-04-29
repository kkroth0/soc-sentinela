# Threat Intelligence - SOC Sentinel

SOC Sentinel é um motor de coleta e análise automatizada especializado em fontes de Threat Intelligence (CTI) e Vulnerability Management (CVE). Roda 24/7 como container Docker e entrega alertas acionáveis diretamente no Microsoft Teams e/ou Telegram.

| Version | Status | Owner |
|---------|--------|-------|
| 1.1.0   | Ativo | @kkroth0 - Matheus Andrade |

---

## Arquitetura Hexagonal

O projeto segue uma arquitetura modular (Hexagonal) para garantir baixo acoplamento.

### 📁 Estrutura do Projeto

```
soc-sentinel/
├── bot.py                  # Orquestrador — agenda e inicializa pipelines
├── config.py               # Variáveis de ambiente centralizadas
├── core/                   # Núcleo compartilhado (Infraestrutura)
│   ├── clients/            # Clientes de API (HTTP, Groq, Teams, Telegram, Graph API)
│   ├── notifications/      # Dispatcher multi-canal (Teams, Telegram)
│   ├── storage.py          # SQLite — Persistência, WAL mode, queries analíticas
│   └── data_manager.py     # Gestão de Ativos com Sincronizador de Nuvem
├── cve/                    # Pipeline de Vulnerabilidades
│   ├── nvd_client.py       # Ingestão NVD API 2.0
│   ├── aliases.py          # Dicionário robusto de aliases para Vendors (AWS, Azure, etc)
│   ├── asset_matcher.py    # Cruzamento CVE × Ativos do Cliente
│   ├── risk_scorer.py      # Enriquecimento com EPSS e CISA KEV
│   └── pipeline.py         # Lógica de decisão e alerta
├── cti/                    # Pipeline de Threat Intel
│   ├── rss_client.py       # Coleta de feeds RSS globais e nacionais
│   ├── scorer.py           # Motor de pontuação de relevância (Scoring)
│   ├── translator.py       # Tradução CTI
│   ├── summarizer.py       # Resumo técnico executivo (LLM)
│   └── pipeline.py         # Orquestração de notícias
├── commands/               # Servidor HTTP (Teams Webhooks) - Porta 8765
├── reports/                # Gerador de relatórios Semanais e Mensais
└── tests/                  # Suíte de 160+ testes automatizados (Pytest)
```

---

## 🗂️ Gestão de Ativos e Aliases (Planilha)

O SOC Sentinel não alerta sobre toda e qualquer CVE do planeta, apenas sobre as que impactam os ativos da sua organização. Isso é feito cruzando dados do NVD com a sua planilha `clients_assets.xlsx`.

Para evitar problemas de *string matching* entre como a Microsoft chama um produto e como o analista escreveu no Excel, o módulo `cve/aliases.py` contém um **dicionário massivo** de *vendors* que cobre Virtualização, Infraestrutura Cloud (AWS, Azure, OCI), Bancos de Dados, EDRs, etc.

### Sincronização em Nuvem (Microsoft Graph API / OneDrive)
O arquivo `clients_assets.xlsx` **não precisa ser atualizado via SSH**.
O bot possui o módulo `graph_client.py` que:
1. Faz autenticação invisível no Entra ID (Client Credentials) e baixa a planilha do **SharePoint Corporativo**.
2. Possui um fallback para leitura de **Link Direto do OneDrive** (para uso pessoal ou anônimo).
3. Atualiza os ativos em memória dinamicamente a cada 12 horas ou sob demanda via comando do Teams.

---

## 💻 Integração Interativa (Teams Webhook)

O SOC Sentinel levanta um servidor HTTP interno (`port 8765`) pronto para se integrar com o recurso **"Outgoing Webhooks"** (Webhooks de Saída) do Microsoft Teams.

Você pode digitar no chat da equipe (ex: `@Sentinel /ListeCVEs`) e o bot responderá com dados diretos do banco SQLite!
**Comandos Disponíveis:**
- `/ListeCVEs`: Mostra as 15 últimas CVEs que impactaram clientes.
- `/ListeCTI`: Mostra as últimas notícias acionáveis de inteligência.
- `/ExportarMes`: Retorna um download direto do CSV com todas as vulnerabilidades mapeadas no mês para a equipe apresentar aos clientes.
- `/AtualizarAtivos`: Força o download imediato da planilha do OneDrive/SharePoint.

---

## 🧠 Inteligência e Scoring (CTI)

O motor de inteligência contra ameaças (CTI) vasculha a internet (feeds RSS globais e regionais) em busca de notícias de cibersegurança. Para não flodar o SOC com alertas irrelevantes, o bot utiliza um **motor de scoring aditivo** para decidir o que é importante.

O *threshold* (nota de corte) atual é de **50 pontos**. Se uma notícia atingir 50 pontos, ela é traduzida, resumida pela IA e enviada como alerta.

| Categoria | Critério (Exemplos de Regex/Palavras) | Pontos |
| :--- | :--- | :--- |
| **Urgência Máxima** | Zero-day, Supply Chain, Exploração Ativa, Patch Emergencial | **+50** |
| **Ativo Monitorado** | Match direto com seu Asset Map (planilha de clientes) | **+50** |
| **Regionalismo** | Brasil, LATAM, .com.br, STF, BCB, Gov.br | **+50** |
| **Ameaças Diretas** | Malware, Ransomware, Backdoor, Wiper, Stealer | **+40** |
| **Comprometimento** | Data Breach, Vazamento de Dados, Incidente Confirmado | **+35** |
| **TTPs & Campanhas** | Phishing, Botnet, C2, Credential Harvesting | **+30** |
| **Radar Local** | Fonte brasileira regionalizada (Layer 4) | **+30** |
| **CVSS Dinâmico** | Menção a score crítico (>= 9.0) no texto original | **+30** |
| **Setor Nacional** | Banco, Financeiro, Governo, Energia, Saúde | **+25** |
| **Grande Escala** | Menção a 1000+ sistemas impactados, *mass exploitation* | **+20** |
| **Vendor Crítico** | Microsoft, Linux, Cloud (AWS/Azure/GCP), Fortinet | **+15** |

> **Deduplicação Inteligente:** Notícias que **não** atingem 50 pontos não são ignoradas pelo banco de dados. Elas são gravadas na tabela com o status `SKIPPED`. Isso evita que a mesma notícia ruim seja processada duas vezes e consuma tokens da API de IA no futuro.

---

## 🛡️ Pipeline de Vulnerabilidades (CVE)

O módulo de CVE consulta a API 2.0 do NIST NVD para obter as vulnerabilidades recém-publicadas.

Para garantir priorização absoluta, o SOC Sentinel enriquece os dados originais do NIST com dois bancos de dados vitais:
1. **CISA KEV (Known Exploited Vulnerabilities):** Se a vulnerabilidade consta no catálogo da CISA, ela ganha a tag vermelha `[CISA KEV]` no alerta do Teams, indicando que a exploração está acontecendo *in the wild* de forma documentada.
2. **EPSS (Exploit Prediction Scoring System):** O bot consulta a probabilidade de uma CVE ser explorada nos próximos 30 dias. Se o score EPSS for maior que 20%, ele é destacado.

> **Regra de Correlação Mandatória:** No pipeline CVE, um alerta **só é disparado** se houver um "match" exato entre o fabricante/produto vulnerável e os ativos cadastrados na sua planilha `clients_assets.xlsx`. Caso contrário, o bot grava a CVE silenciosamente no SQLite.

---

## 🤖 Refinamento com LLM Llama 3.3

O fluxo de processamento de inteligência prioriza eficiência de tokens e rigor técnico:
- **Tradução e Inteligência:** Utiliza exclusivamente o motor de IA da **Groq (Llama 3)** para converter conteúdo para PT-BR e gerar resumos executivos, mantendo o rigor técnico e preservando jargões de cibersegurança (ex: *Buffer Overflow*, *Command Injection*).
- **Resumo Executivo:** O modelo de raciocínio avançado `llama-3.3-70b-versatile` (Groq) reestrutura o texto extenso da notícia original para a visão de um analista nível 1/2 em três parágrafos: *O que aconteceu → O Impacto → Ação Recomendada*.

---

## ☁️ Deploy no Microsoft Azure (Recomendado)

O Sentinel foi desenhado para ser econômico. Se você possui créditos na Azure, a arquitetura ideal de baixo custo é:
1. **Azure Virtual Machine (Linux Ubuntu - B1s ou B2s):** O banco SQLite (em modo WAL) roda perfeitamente no disco local sem os problemas de lock de *Network Drives*. Consome pouquíssimo crédito.
2. **Cloudflare Tunnel (Opcional, porém Recomendado):** Para que o Microsoft Teams possa enviar os comandos POST para o seu servidor, a URL precisa ser **HTTPS**. Você pode instalar o `cloudflared` na sua VM em 2 minutos para rotear o tráfego seguramente para a porta 8765, sem precisar abrir portas no Firewall da Azure (NSG) ou configurar certificados Let's Encrypt na mão.

---

## ⚙️ Configuração Principal (.env)

| Variável | Descrição |
|----------|-----------|
| `NVD_API_KEY` | Chave da API do NIST NVD |
| `GROQ_API_KEY` | Chave do Groq Cloud (Para rodar o Llama 3.3) |
| `GRAPH_CLIENT_ID` | (Opcional) App ID do Microsoft Entra ID para ler o SharePoint |
| `ONEDRIVE_DIRECT_URL` | (Fallback) Link direto para a planilha de ativos |
| `TEAMS_WEBHOOK_URL`| URL do canal do Teams para alertas proativos |
| `LOG_LEVEL` | INFO, DEBUG, WARNING (Ajustável sem reconstruir o Docker) |

---

## 🥇 Regras de Ouro da Arquitetura

1. **Eficiência de Tokens:** Textos são truncados e limitados a 12.000 caracteres antes de atingir o LLM (Llama 3.3). Previne estouro de limite da API.
2. **Zero Acoplamento:** O Groq LLM é um cliente HTTP puro e não carrega lógica de negócio. Os prompts moram inteiramente nos módulos de domínio (`cve/translator.py`, `cti/summarizer.py`).
3. **Isolamento de Falhas:** Os módulos CVE e CTI são completamente independentes no *APScheduler*. Se o NVD do governo americano cair, o CTI pode continuar operando normalmente.

---

## 🧪 Testes e Qualidade

O projeto mantém uma suíte rigorosa com mais de **160 testes unitários** passando, cobrindo:
- Lógica de Alerta (CVE/CTI) e Motor de Scoring.
- Banco de Dados (Query filters e agregação).
- Clientes de API, Tradução e Formatação.

Para rodar os testes localmente:
```bash
source .venv/bin/activate
python -m pytest tests/ -v
```
