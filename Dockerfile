FROM node:20-slim AS frontend-build

WORKDIR /frontend

COPY frontend/package*.json ./
COPY frontend/index.html frontend/vite.config.js ./
COPY frontend/public ./public
COPY frontend/src ./src

RUN npm ci
RUN npm run build


FROM python:3.11-slim

WORKDIR /app

# Force Python to flush stdout/stderr immediately so logs appear in
# `docker compose logs -f` without buffering delay.
ENV PYTHONUNBUFFERED=1

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install system libraries required by pycti (python-magic needs libmagic1)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies into the system Python (no venv needed in container)
RUN uv pip install --system --no-cache -r pyproject.toml

# Copy application code
COPY app.py ./
COPY tests ./tests
COPY sources ./sources
COPY core ./core
COPY cases ./cases
COPY utils ./utils
COPY db ./db
COPY integrations ./integrations
COPY scripts ./scripts
COPY config ./config
COPY --from=frontend-build /frontend/dist ./frontend/dist

RUN mkdir -p /app/data


EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
