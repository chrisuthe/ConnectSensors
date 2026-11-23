# cs-mailbox in a container. Build from the repository root, which holds the spec's
# csframe.py next to the server:
#
#   docker build -f mailbox/Dockerfile -t cs-mailbox .
#   docker run -p 8443:8443 -v cs-mailbox:/data -v /etc/letsencrypt:/tls:ro cs-mailbox \
#       --host mailbox.example --tls-cert /tls/fullchain.pem --tls-key /tls/privkey.pem
FROM python:3.13-slim

RUN pip install --no-cache-dir "cryptography>=43" "websockets>=14" \
    && useradd --system --uid 10001 mailbox \
    && mkdir /data && chown mailbox /data

WORKDIR /app
# The checkout's layout, so cs_mailbox.py finds ../spec/tools/csframe.py.
COPY spec/tools/csframe.py spec/tools/csframe.py
COPY mailbox/cs_mailbox.py mailbox/cs_mailbox.py

USER mailbox
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["python3", "-I", "mailbox/cs_mailbox.py", "--key-file", "/data/server.key"]
