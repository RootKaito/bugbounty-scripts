# Imagem oficial do Playwright já vem com Chromium + todas as deps de
# sistema instaladas — evita o problema de "which python/pip" que
# apareceu numa tentativa anterior rodando isso num sandbox genérico.
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY watch.py .

# /data é onde o Volume do Railway deve ser montado (guarda o estado
# entre execuções — ver README.md).
ENV STATE_PATH=/data/seen_programs.json

CMD ["python3", "watch.py"]
