FROM python:3.12-slim AS builder

ARG POETRY_VERSION=2.4.1

ENV POETRY_VIRTUALENVS_IN_PROJECT=1
ENV POETRY_VIRTUALENVS_CREATE=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV POETRY_CACHE_DIR=/opt/.cache

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /app

COPY pyproject.toml poetry.lock /app/

RUN poetry install --no-root && rm -rf $POETRY_CACHE_DIR

FROM python:3.12-slim AS runtime

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
COPY *.py /app/

WORKDIR /app
ENTRYPOINT ["python"]
CMD ["client.py"]
