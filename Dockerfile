FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Dependencies first for better layer caching.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
COPY knowledge ./knowledge
COPY intel ./intel
COPY policy ./policy
COPY samples ./samples
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH" \
    CYBOT_DATABASE_URL="sqlite:////app/data/cybot.db" \
    CYBOT_CHROMA_PATH="/app/data/chroma" \
    CYBOT_CHECKPOINT_PATH="/app/data/checkpoints.db"

# Bake the ONNX embedding model into the image so startup works offline.
RUN python -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ONNXMiniLM_L6_V2()(['warmup'])"

RUN useradd --create-home --uid 1000 cybot \
    && mkdir -p /app/data \
    && cp -r /root/.cache /home/cybot/.cache \
    && chown -R cybot:cybot /app/data /home/cybot/.cache
USER cybot

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["cybot", "serve", "--host", "0.0.0.0", "--port", "8000"]
