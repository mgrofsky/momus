# Local browser bridge for the lab only. It has no app data, secrets, or scanner network.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50
RUN install -d -m 0755 /app
COPY --chown=10001:10001 --chmod=0444 proxy/server.py /app/server.py
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python3", "-I", "-B", "/app/server.py"]
