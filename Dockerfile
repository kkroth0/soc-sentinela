# ══════════════════════════════════════════════════════════════════════
# SOC SENTINEL — Dockerfile
# ══════════════════════════════════════════════════════════════════════
FROM python:3.12-slim

# Metadados
LABEL maintainer="SOC Team"
LABEL description="SOC Sentinel — Threat Intelligence & Vulnerability Management Bot"
LABEL version="1.1.0"

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=UTC

# Configura timezone e instala dependências básicas
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN groupadd --gid 1000 sentinel && \
    useradd --uid 1000 --gid sentinel --create-home sentinel

# Diretório de trabalho
WORKDIR /app

# Instalar dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código-fonte
COPY . .

# Criar diretório de dados
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app

# Trocar para usuário não-root
USER sentinel

# Health check
HEALTHCHECK --interval=60s --timeout=10s --retries=3 --start-period=30s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${COMMAND_PORT:-8765}/health')" || exit 1

# Expor porta do servidor de comandos
EXPOSE ${COMMAND_PORT:-8765}

# Entrypoint
CMD ["python", "bot.py"]
