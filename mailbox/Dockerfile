# cs-mailbox in a container, published as ghcr.io/chrisuthe/cs-mailbox. Build from
# the repository root, which holds the connectsensors package and the spec's
# csframe.py it loads:
#
#   docker build -f mailbox/Dockerfile -t cs-mailbox .
#
# Configure with arguments or CS_MAILBOX_* variables (mailbox/container_entry.py);
# see mailbox/README.md, "Container image".

# python:3.13-slim
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50

# Set by the release workflow, which also labels the revision; a local build is "dev".
ARG VERSION=dev
LABEL org.opencontainers.image.title="cs-mailbox" \
      org.opencontainers.image.description="Reference mailbox server for ConnectSensors federation (spec 09)" \
      org.opencontainers.image.source="https://github.com/chrisuthe/ConnectSensors" \
      org.opencontainers.image.url="https://github.com/chrisuthe/ConnectSensors/tree/main/mailbox" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# Exact versions, so a release rebuilt from the same tag gets the same libraries.
RUN pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore "cryptography==50.0.2" "websockets==17.4" \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mailbox \
    && mkdir /data && chown mailbox /data

WORKDIR /app
# The checkout's layout: cs_mailbox.py imports ../python/connectsensors, which loads
# ../spec/tools/csframe.py.
COPY spec/tools/csframe.py spec/tools/csframe.py
COPY python/connectsensors python/connectsensors
COPY mailbox/cs_mailbox.py mailbox/container_entry.py mailbox/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CS_MAILBOX_PORT=8443

USER 10001
VOLUME /data
EXPOSE 8443
# A TCP connect: works with TLS and behind a proxy alike, and needs no client key.
# It follows CS_MAILBOX_PORT, so change the port with that rather than --port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["python3", "-I", "-c", "import os, socket; socket.create_connection(('127.0.0.1', int(os.environ['CS_MAILBOX_PORT'])), 3).close()"]
ENTRYPOINT ["python3", "-I", "mailbox/container_entry.py"]
