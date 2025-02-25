# This Dockerfile is mainly used for load testing with locust.

FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./
COPY demo_project/ ./demo_project/
COPY demo_project/README.md ./README.md
COPY src/ ./src/

# Install dependencies using uv
RUN uv add fastapi --extra standard && \
    uv add pydantic-settings && \
    uv sync --frozen --no-dev

# Run the application.
CMD ["/app/.venv/bin/fastapi", "run", "demo_project/main.py", "--port", "8001", "--host", "0.0.0.0", "--workers", "4"]
