#!/bin/bash
set -euo pipefail

CONFIG_FILE="/etc/madcat/config.lua"
RUN_SCRIPT="/opt/madcat/scripts/run_madcat.sh"
LOG_DIR="/data"
STARTUP_LOG="/var/log/madcat/startup.log"
PATCH_FILE="/opt/madcat/bin/madcat_config.patch"
ENRICHED_LOG="$LOG_DIR/enriched.json.log"

touch "$ENRICHED_LOG"
chmod 644 "$ENRICHED_LOG"
chown -R madcat:madcat "$LOG_DIR"

# === Startup-Log separat mitloggen ==========================================
mkdir -p "$(dirname "$STARTUP_LOG")"
exec > >(tee -a "$STARTUP_LOG") 2>&1

echo "🔧 [STARTUP] Initialisiere MADCAT-Container..."

# === Patch anwenden =========================================================
if [[ -f "$PATCH_FILE" ]]; then
  echo "🩹 Wende Patch an: $PATCH_FILE"
  patch --batch --forward -p1 < "$PATCH_FILE" || \
      echo " Kontext passt nicht oder schon gepatcht – übersprungen."
else
  echo "ℹ️ Keine Patch-Datei unter $PATCH_FILE gefunden – überspringe."
fi

# === Audit vorbereiten ======================================================
mkdir -p /var/log/audit
touch /var/log/audit/audit.log
chown root:root /var/log/audit/audit.log

echo "⇒ Starte auditd..."
auditd start || echo " auditd konnte nicht starten – fahre trotzdem fort."
sleep 1

# === HIVE-IP in config.lua setzen ===========================================
if [[ -n "${HIVE_IP:-}" ]]; then
  echo "🔧 Setze HIVE_IP in config.lua auf: $HIVE_IP"
  sed -i "s|<HIVE_SERVER_IP>|$HIVE_IP|g" "$CONFIG_FILE"
else
  echo "  HIVE_IP nicht gesetzt – nutze Platzhalter in config.lua"
fi

# === Log-Verzeichnisse & Dateien anlegen ====================================
echo "📁 Erstelle Logverzeichnisse & -dateien..."
mkdir -p "$LOG_DIR" /tmp /var/log/madcat
touch "$LOG_DIR"/{madcat.log,monitoring.log,\
error.enrichment.log,error.udp.log,error.icmp.log,\
error.raw.log,error.tcp.log,error.tcppost.log}
chmod -R 755 "$LOG_DIR"

# === sudo in Skripten entfernen (Hardening) =================================
find /opt/madcat/scripts -type f -exec sed -i 's/\bsudo\b //g' {} + || true

# ============================================================================ #
# ===  INTERFACE & IP FESTLEGEN – ENV hat Vorrang vor Auto-Erkennung  =========
# ============================================================================ #
if [[ -n "${MADCAT_INTERFACE:-}" ]]; then
  MADCAT_IF="$MADCAT_INTERFACE"
  # Falls IP nicht mitgegeben: automatisch auslesen
  MADCAT_IP="${MADCAT_IP:-$(ip -4 addr show "$MADCAT_IF" \
               | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)}"
  echo "🌐 MADCAT_INTERFACE durch ENV vorgegeben: '$MADCAT_IF' ($MADCAT_IP)"
else
  echo "📡 Verfügbare Interfaces:"
  ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|docker|br|vir|veth'

  # Standard-Interface ermitteln, um es auszuschließen
  DEFAULT_IF=${MGMT_INTERFACE:-$(ip route | awk '/default/ {print $5}' | head -n1)}
  MADCAT_IF=$(ip -o link show | awk -F': ' '{print $2}' \
             | grep -vE "lo|docker|br|vir|veth|${DEFAULT_IF}" | head -n1)

  if [[ -z "$MADCAT_IF" ]]; then
    echo " Kein alternatives Interface gefunden. Abbruch."
    exit 1
  fi

  MADCAT_IP=$(ip -4 addr show "$MADCAT_IF" \
              | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
  if [[ -z "$MADCAT_IP" ]]; then
    echo " Konnte IP nicht ermitteln. Abbruch."
    exit 1
  fi
  echo "🌐 Verwende Interface '$MADCAT_IF' mit IP '$MADCAT_IP'"
fi

# === config.lua & Monitoring-Config patchen ==================================
sed -i "s|<REPLACE_IFACE>|$MADCAT_IF|g" "$CONFIG_FILE"
sed -i "s|<REPLACE_IP>|$MADCAT_IP|g"    "$CONFIG_FILE"
sed -i "s|wlp8s0|$MADCAT_IF|g; s|enp9s0|$MADCAT_IF|g" \
       "/etc/madcat/monitoring_config.py"

# === iptables-Regeln im Run-Script anpassen =================================
echo "🔧 Aktiviere IP-Forwarding im Kernel"
sysctl -w net.ipv4.ip_forward=1 || echo "  Konnte net.ipv4.ip_forward nicht setzen"

sed -i -E \
  -e "s/(iptables .* -i )[^ ]+/\1${MADCAT_IF}/g" \
  -e "s/(--to(=destination)? )[^ ]+/\1${MADCAT_IP}:65535/g" \
  "$RUN_SCRIPT"

# === Modul-Existenzprüfung ===================================================
echo "🔍 Prüfe MADCAT-Komponenten..."
missing=0
for f in /opt/madcat/{udp_ip_port_mon,icmp_mon,raw_mon,tcp_ip_port_mon,\
enrichment_processor.py,tcp_ip_port_mon_postprocessor.py}; do
  [[ -f "$f" ]] || { echo " Fehlend: $f"; missing=1; }
done
(( missing == 0 )) || { echo " Abbruch."; exit 1; }

# === Named Pipes anlegen =====================================================
rm -f /tmp/logs.erm /tmp/connect_json.tpm /tmp/header_json.tpm
mkfifo /tmp/logs.erm /tmp/connect_json.tpm /tmp/header_json.tpm

chmod +x "$RUN_SCRIPT"
ln -sf /opt/madcat/bin/enrichment_processor.py /opt/madcat/enrichment_processor.py

# === MADCAT starten ==========================================================
echo " Starte MADCAT..."
(bash "$RUN_SCRIPT" >> "$LOG_DIR/madcat.log" 2>> "$LOG_DIR/error.tcp.log") &
MADCAT_PID=$!
sleep 3

# === Monitoring starten ======================================================
echo "📡 Starte Monitoring..."
/usr/bin/python3 /opt/madcat/bin/monitoring/monitoring.py \
  /etc/madcat/monitoring_config.py \
  >> "$LOG_DIR/monitoring.log" 2>> "$LOG_DIR/error.monitoring.log" &

# === RL-Redirector starten ===================================================
REDIRECTOR_SCRIPT="/opt/madcat/redirector.py"
if [[ -f "$REDIRECTOR_SCRIPT" ]]; then
  echo "🔁 Starte RL-DNAT-Redirector..."
  export HIVE_IP="$HIVE_IP"
  export MADCAT_INTERFACE_IP="$MADCAT_IP"
  /usr/bin/env python3 "$REDIRECTOR_SCRIPT" &
else
  echo " Kein Redirector gefunden unter $REDIRECTOR_SCRIPT"
fi

wait  # Container offen halten
