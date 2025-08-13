#!/usr/bin/env bash
CERTDIR=/usr/share/filebeat/certs

# warte, bis HIVE die Zertifikate ins certs‑Verzeichnis gemounted hat
while [ ! -f "$CERTDIR/logstash.crt" ] || [ ! -f "$CERTDIR/logstash.key" ]; do
  echo "→ warte auf Zertifikate in $CERTDIR…"
  sleep 2
done


# dann Filebeat starten
exec /usr/local/bin/docker-entrypoint filebeat \
  -e \
  -strict.perms=false
