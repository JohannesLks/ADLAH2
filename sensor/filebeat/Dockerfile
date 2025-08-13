FROM docker.elastic.co/beats/filebeat:8.6.0

USER root
WORKDIR /usr/share/filebeat

# 1) Copy Deine Config und setze Owner & Permissions
COPY dist/filebeat.yml ./filebeat.yml
RUN chown root:root /usr/share/filebeat/filebeat.yml \
 && chmod 0644   /usr/share/filebeat/filebeat.yml

# 2) Copy das Entrypoint‑Skript
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 3) Stelle das Cert‑Verzeichnis bereit und schütze es
RUN mkdir -p /usr/share/filebeat/certs \
 && chown filebeat:filebeat /usr/share/filebeat/certs

# 4) Zurück auf non‑privileged User
USER filebeat

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
