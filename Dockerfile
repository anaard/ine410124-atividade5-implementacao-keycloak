FROM python:3.12-alpine AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt ./

RUN apk add --no-cache libgcc \
    && pip install --no-cache-dir --no-compile --only-binary=:all: -r requirements.txt

COPY telemedicina ./telemedicina
COPY templates ./templates
COPY scripts ./scripts

RUN mkdir -p runtime infra && chown -R 1000:1000 runtime infra

USER 1000:1000

CMD ["python", "-m", "telemedicina.portal"]
