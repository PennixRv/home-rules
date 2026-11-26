FROM alpine:3.22

RUN apk add --no-cache ca-certificates git nginx python3 py3-yaml tzdata
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY LICENSE prm_release.py rule_changes.py verify_release.py mihomo.py schedule.py origin.py test_release.py nginx.conf public-paths.conf /app/
CMD ["python3", "/app/schedule.py"]
