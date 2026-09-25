# syntax=docker/dockerfile-upstream:master
FROM busybox:latest AS deps
COPY pyproject.toml /deps.toml
RUN sed -i 's/^version = ".*"/version = "0.0.0"/' /deps.toml



FROM python:3.14-slim AS builder

ARG POETRY_VERSION=2.4.1

ENV POETRY_VIRTUALENVS_IN_PROJECT=1
ENV POETRY_VIRTUALENVS_CREATE=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV POETRY_CACHE_DIR=/opt/.cache

RUN python -m pip install "poetry==${POETRY_VERSION}"

WORKDIR /app

COPY --from=deps /deps.toml /app/pyproject.toml
COPY poetry.lock /app/

ARG POETRY_INSTALLER_MAX_WORKERS=4
ENV POETRY_INSTALLER_MAX_WORKERS=$POETRY_INSTALLER_MAX_WORKERS
RUN poetry install --only main && rm -rf $POETRY_CACHE_DIR



FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY --from=builder /app/.venv /app/.venv
COPY . /app

WORKDIR /app
ENTRYPOINT ["python"]
CMD ["client.py"]
