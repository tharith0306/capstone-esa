FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# libgomp: OpenMP runtime used by XGBoost
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY app ./app
# Optional extras: "graph" (Neo4j driver) by default; add "deep" for the PyTorch sequence models,
# e.g.  docker compose build --build-arg EXTRAS=graph,deep backend
ARG EXTRAS=graph
RUN pip install --no-cache-dir ".[${EXTRAS}]"

COPY sample_data ./sample_data
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["./docker-entrypoint.sh"]
