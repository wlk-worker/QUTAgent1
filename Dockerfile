FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq file \
    && mkdir -p /app && dpkg-query -W > /app/tool-versions.txt \
    && python --version >> /app/tool-versions.txt && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 agent && mkdir -p /ctfy/work && chown agent:agent /ctfy/work
COPY agent /app/agent
WORKDIR /ctfy/work
USER agent
ENTRYPOINT ["python", "/app/agent/main.py"]

