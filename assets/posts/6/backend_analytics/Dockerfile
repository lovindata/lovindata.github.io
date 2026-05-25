FROM python:3.12-slim AS backend_analytics_builder
WORKDIR /backend_analytics
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/0.9.22/install.sh | sh
COPY backend_analytics/pyproject.toml backend_analytics/uv.lock ./
RUN /root/.local/bin/uv sync --locked --no-cache --no-default-groups \
    && rm pyproject.toml uv.lock



FROM python:3.12-slim AS backend_analytics
WORKDIR /backend_analytics
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=backend_analytics_builder /backend_analytics .
COPY backend_analytics/main.py ./
COPY backend_analytics/src ./src
ENV DOTENV_PATH=""
ENV LOG_LEVEL="info"
ENV WATCHFILES="false"
ENV FASTAPI_ALLOW_CORS="false"
ENV FASTAPI_SHOW_UNHANDLED_EXCEPTIONS="false"
ENV FASTAPI_DOCS="false"
ENTRYPOINT [ ".venv/bin/python3", "main.py" ]
