FROM alpine:3.22

RUN apk add --no-cache ca-certificates curl git nginx python3 py3-yaml tzdata \
    && apk add --no-cache --virtual .build-deps py3-pip \
    && python3 -m pip install --no-cache-dir --break-system-packages --only-binary=:all: --no-deps maxminddb==3.3.0 \
    && apk del .build-deps
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY --chmod=0644 LICENSE prm_release.py rule_changes.py verify_release.py mihomo.py schedule.py origin.py test_release.py nginx.conf public-paths.conf /app/
CMD ["python3", "/app/schedule.py"]
