FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends make \
    && python -m pip install --no-cache-dir pytest \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 PYTHONPYCACHEPREFIX=/tmp/python-cache
WORKDIR /lab/workspace/Day26-Colosseum-Agent-Arena-Kit
