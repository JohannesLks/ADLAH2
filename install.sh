#!/usr/bin/env bash

# =====================================
# ADLAH Installation Script
# Unterstützt: Hive & Sensor
# Autor: Johannes Möller – (überarbeitet 2025-05-25)
# =====================================

# ── Exit-Codes ───────────────────────────────────────────────────────────────
EXIT_SUCCESS=0
EXIT_INVALID_PARAMS=1
EXIT_MISSING_DEPS=2
EXIT_PERMISSION_DENIED=3
EXIT_RSYNC_FAILED=4
EXIT_DOCKER_FAILED=5
EXIT_SYSTEM_SERVICE_FAILED=6
EXIT_QUIT=8

# ── Globale Variablen ─────────────────────────────────────────────────────────
USER_NAME=$(whoami)
REQUIREMENTS_FILE="./requirements.txt"
ENV_FILE="$HOME/.adlah_env"
SSH_KEY_PATH="$HOME/.ssh/id_rsa"
SSH_PORT=22
KIBANA_ENCRYPTION_KEY=$(openssl rand -base64 32)

# ── Hilfsfunktionen ──────────────────────────────────────────────────────────
check_command() { command -v "$1" >/dev/null 2>&1; }

# Hinzugefügte Farben und Notizen
C0='\e[0m'; C1='\e[36m'; C2='\e[32m'; C3='\e[33m'; C4='\e[31m'
info() { echo -e "${C2}[install]${C0} $*"; }
note() { echo -e "${C1}[install]${C0} $*"; }
warn() { echo -e "${C3}[install] $*${C0}"; }
die()  { echo -e "${C4}[install] $*${C0}" >&2; exit 1; }

# Robuste Subprozess-Ausführung mit Exit-Code-Behandlung
run_or_die() {
    local cmd="$*"
    local exit_code
    info "Führe aus: $cmd"
    eval "$cmd"
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        die "Befehl fehlgeschlagen (Exit-Code: $exit_code): $cmd"
    fi
    return $exit_code
}

# Sichere Subprozess-Ausführung mit Warnung bei Fehlern
run_or_warn() {
    local cmd="$*"
    local exit_code
    info "Führe aus: $cmd"
    eval "$cmd"
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        warn "Befehl fehlgeschlagen (Exit-Code: $exit_code): $cmd"
    fi
    return $exit_code
}

# Prüfe ob Verzeichnis/Datei existiert
check_path_exists() {
    local path="$1"
    local description="${2:-$path}"
    if [[ ! -e "$path" ]]; then
        die "Erforderlicher Pfad nicht gefunden: $description ($path)"
    fi
}

# Prüfe ob Verzeichnis existiert und nicht leer ist
check_dir_not_empty() {
    local dir="$1"
    local description="${2:-$dir}"
    check_path_exists "$dir" "$description"
    if [[ ! -d "$dir" ]]; then
        die "Pfad ist kein Verzeichnis: $description ($dir)"
    fi
    if [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
        die "Verzeichnis ist leer: $description ($dir)"
    fi
}

abort_if_fail() { 
    local cmd="$*"
    local exit_code
    eval "$cmd"
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        die "Kritischer Fehler bei: $cmd (Exit-Code: $exit_code)"
    fi
    return $exit_code
}

# Liste aller phys./virtuellen NICs außer Loopback & Container-Bridges
list_nics() { 
    local nics
    nics=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|docker|br|vir|veth')
    if [[ -z "$nics" ]]; then
        die "Keine Netzwerk-Interfaces gefunden"
    fi
    echo "$nics"
}

# ── Validierungsfunktion ─────────────────────────────────────────────────────
validate_installation_parameters() {
  local errors=()
  local warnings=()

  info "🔍 Validiere Installationsparameter..."

  # Prüfe Installations-Typ
  if [[ -z "$INSTALL_TYPE" ]]; then
    errors+=("Installationstyp ist nicht gesetzt (hive oder sensor)")
  elif [[ "$INSTALL_TYPE" != "hive" && "$INSTALL_TYPE" != "sensor" ]]; then
    errors+=("Ungültiger Installationstyp: '$INSTALL_TYPE' (muss 'hive' oder 'sensor' sein)")
  fi

  # Hive-spezifische Validierung
  if [[ "$INSTALL_TYPE" == "hive" ]]; then
    if [[ -z "$KIBANA_USER" ]]; then
      errors+=("Kibana-Benutzername ist für Hive-Installation erforderlich")
    elif [[ ! "$KIBANA_USER" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      errors+=("Kibana-Benutzername enthält ungültige Zeichen (nur a-z, A-Z, 0-9, _, - erlaubt)")
    fi

    if [[ -z "$KIBANA_PASSWORD" ]]; then
      errors+=("Kibana-Passwort ist für Hive-Installation erforderlich")
    elif [[ ${#KIBANA_PASSWORD} -lt 8 ]]; then
      warnings+=("Kibana-Passwort ist sehr kurz (weniger als 8 Zeichen)")
    fi
  fi

  # Sensor-spezifische Validierung
  if [[ "$INSTALL_TYPE" == "sensor" ]]; then
    if [[ -z "$HIVE_IP" ]]; then
      errors+=("Hive-IP ist für Sensor-Installation erforderlich")
    elif ! [[ "$HIVE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      errors+=("Ungültige Hive-IP-Adresse: '$HIVE_IP'")
    fi

    if [[ -z "$MADCAT_IF" ]]; then
      errors+=("MADCAT-Interface ist für Sensor-Installation erforderlich")
    else
      # Prüfe ob Interface existiert
      if ! list_nics | grep -qx "$MADCAT_IF"; then
        errors+=("MADCAT-Interface '$MADCAT_IF' existiert nicht")
      fi
    fi

    # Optional: Management Interface validieren
    if [[ -n "$MGMT_IF" ]]; then
      if ! list_nics | grep -qx "$MGMT_IF"; then
        warnings+=("Management-Interface '$MGMT_IF' existiert nicht und wird ignoriert")
      fi
    fi
  fi

  # System-Voraussetzungen prüfen
  if ! check_command docker; then
    warnings+=("Docker ist nicht installiert - wird automatisch installiert")
  fi

  if ! check_command docker-compose && ! docker compose version >/dev/null 2>&1; then
    warnings+=("Docker Compose ist nicht verfügbar - wird automatisch installiert")
  fi

  # SSH-Key prüfen
  if [[ ! -f "$SSH_KEY_PATH" ]]; then
    warnings+=("SSH-Key nicht gefunden - wird automatisch generiert")
  fi

  # Berechtigungen prüfen
  if [[ $EUID -eq 0 ]]; then
    errors+=("Script sollte nicht als root ausgeführt werden")
  fi

  # Verzeichnis-Berechtigungen prüfen
  if [[ ! -w "$HOME" ]]; then
    errors+=("Keine Schreibberechtigung im Home-Verzeichnis")
  fi

  # Zeige Warnings an
  if [[ ${#warnings[@]} -gt 0 ]]; then
    echo
    for warning in "${warnings[@]}"; do
      warn "WARNUNG: $warning"
    done
  fi

  # Zeige Errors an und beende bei Fehlern
  if [[ ${#errors[@]} -gt 0 ]]; then
    echo
    die "Validierungsfehler gefunden:${errors[*]/#/$'\n  - '}"
  fi

  info "Alle Parameter sind korrekt gesetzt"
  echo
}

run_compose_stack() {
  local dir="$1"
  echo "Starte Docker Compose in: $dir"
  cd "$dir" || die "Konnte nicht in Verzeichnis wechseln: $dir"
  
  # Prüfe ob docker-compose.yml existiert
  check_path_exists "docker-compose.yml" "Docker Compose Konfiguration"
  
  # Entferne evtl. alte Container, um Typ-Konflikte bei Bind-Mounts (File vs. Dir) zu vermeiden
  run_or_warn docker compose down -v --remove-orphans
  
  # Starte Stack mit Fehlerbehandlung
  if ! docker compose up -d --force-recreate 2>&1 | tee /tmp/docker_compose.log; then
    echo "Docker Compose fehlgeschlagen:"
    cat /tmp/docker_compose.log
    die "Docker Compose Stack konnte nicht gestartet werden"
  fi
  
  # Prüfe ob Container laufen
  if ! docker compose ps | grep -q "Up"; then
    die "Docker Compose Container laufen nicht korrekt"
  fi
  
  docker compose ps
}

# ---------------------------------------------------------------------------
# Neue robuste Helfer
# ---------------------------------------------------------------------------
ensure_dir() {
  # Erstellt Verzeichnis rekursiv (ggf. mit sudo) und setzt Ownership auf den
  # aktuellen Benutzer, damit nachfolgende Schreiboperationen ohne sudo
  # funktionieren.
  local path="$1"
  run_or_die sudo mkdir -p "$path"
  run_or_die sudo chown "$USER":"$USER" "$path"
}

cleanup_maybe_dir() {
  # Löscht eine bestehende Datei oder ein Verzeichnis gleichen Namens (sudo),
  # wenn es existiert. Verhindert "Is a directory"-Fehler.
  local target="$1"
  if [ -e "$target" ]; then
    run_or_warn sudo rm -rf "$target"
  fi
}


# ────────────────────────────────────────────────────────────────────────────

# ── Parameter-Parsing & Moduswahl ───────────────────────────────────────────
usage() {
  cat <<EOF
ADLAH Installation Script

Usage: $0 --type <hive|sensor> [OPTIONS]

Required for --type=hive:
  --user <name>          Kibana username.
  --password <pass>      Kibana password. Can also be passed via \$PASS.

Required for --type=sensor:
  --hive-ip <ip>         IP address of the Hive server.
  --madcat-if <iface>    Network interface for MADCAT to listen on.

Optional:
  --mgmt-if <iface>      (Sensor only) Management interface for SSH/IAP.
  -y, --yes              Automatic yes to prompts; assumes automation.
  -h, --help             Show this help message.

Examples:
  $0 --type hive --user admin --password mypass
  $0 --type sensor --hive-ip 192.168.1.100 --madcat-if eth0
  $0 --type hive  # Interactive mode for missing parameters

Exit Codes:
  $EXIT_SUCCESS - Erfolgreich
  $EXIT_INVALID_PARAMS - Ungültige Parameter
  $EXIT_MISSING_DEPS - Fehlende Abhängigkeiten
  $EXIT_PERMISSION_DENIED - Berechtigungsfehler
  $EXIT_RSYNC_FAILED - Kopierfehler
  $EXIT_DOCKER_FAILED - Docker-Fehler
  $EXIT_SYSTEM_SERVICE_FAILED - Systemdienst-Fehler
  $EXIT_QUIT - Benutzer-Abbruch
EOF
  exit 0
}

# Standardwerte
INSTALL_TYPE=""
KIBANA_USER=""
KIBANA_PASSWORD=""
HIVE_IP=""
MADCAT_IF=""
MGMT_IF=""
AUTO_CONFIRM="no"

# Argumente parsen
if [[ $# -gt 0 ]]; then
  # Temp-Argument für Passwort, um Fehler bei leerem $PASS zu vermeiden
  CLI_PASSWORD="CLI_PASSWORD_NOT_SET"

  # Argumente parsen
  eval set -- "$(getopt -o 'yh' --longoptions 'type:,user:,password:,hive-ip:,madcat-if:,mgmt-if:,yes,help' -n "$0" -- "$@")"

  while true; do
    case "$1" in
      --type) INSTALL_TYPE=$(echo "$2" | tr '[:upper:]' '[:lower:]'); shift 2;;
      --user) KIBANA_USER="$2"; shift 2;;
      --password) CLI_PASSWORD="$2"; shift 2;;
      --hive-ip) HIVE_IP="$2"; shift 2;;
      --madcat-if) MADCAT_IF="$2"; shift 2;;
      --mgmt-if) MGMT_IF="$2"; shift 2;;
      -y|--yes) AUTO_CONFIRM="yes"; shift;;
      -h|--help) usage; shift;;
      --) shift; break;;
      *) die "Interner Fehler beim Parsen!";;
    esac
  done

  # Passwort aus CLI oder $PASS-Variable übernehmen
  if [[ "$CLI_PASSWORD" != "CLI_PASSWORD_NOT_SET" ]]; then
    KIBANA_PASSWORD="$CLI_PASSWORD"
  elif [[ -n "${PASS:-}" ]]; then
    KIBANA_PASSWORD="$PASS"
  fi
else
  # Keine Argumente - zeige kurze Hilfe und frage interaktiv
  echo "ADLAH Installation Script"
  echo "Verwende: $0 --help für vollständige Optionen"
  echo "Oder starte ohne Parameter für interaktiven Modus"
  echo
fi

# Interaktive Abfrage fehlender Parameter
if [[ -z "$INSTALL_TYPE" ]]; then
  echo -e "\nWillkommen bei ADLAH"
  echo "[H] Hive – ELK + RL-Agent"
  echo "[S] Sensor – MADCAT + Logweiterleitung"
  echo "[Q] Quit"

  while true; do
    read -rp "Auswahl (h/s/q): " choice
    case "${choice,,}" in
      h) INSTALL_TYPE="hive"; break;;
      s) INSTALL_TYPE="sensor"; break;;
      q) echo "Abgebrochen."; exit $EXIT_QUIT;;
      *) warn "Ungültig. Bitte h, s oder q.";;
    esac
  done
fi

# Hive-spezifische interaktive Abfragen
if [[ "$INSTALL_TYPE" == "hive" ]]; then
  if [[ -z "$KIBANA_USER" ]]; then
    read -rp "Kibana-Nutzername: " KIBANA_USER
  fi
  if [[ -z "$KIBANA_PASSWORD" ]]; then
    read -rsp "Kibana-Passwort: " KIBANA_PASSWORD; echo
  fi
fi

# Sensor-spezifische interaktive Abfragen
if [[ "$INSTALL_TYPE" == "sensor" ]]; then
  if [[ -z "$HIVE_IP" ]]; then
    read -rp "Hive-IP (z. B. 10.1.0.10): " HIVE_IP
  fi
  if [[ -z "$MADCAT_IF" ]]; then
    echo
    echo "Verfügbare Interfaces:"
    list_nics
    while true; do
      read -rp "Interface für MADCAT (Packet-Capture/DNAT): " MADCAT_IF
      list_nics | grep -qx "$MADCAT_IF" && break
      warn "Ungültiges Interface."
    done
  fi
  if [[ -z "$MGMT_IF" ]]; then
    read -rp "Interface für Management (IAP/SSH) [Enter = Auto]: " MGMT_IF
  fi
fi

# ── Parameter-Validierung ───────────────────────────────────────────────────
# Validiere alle Parameter BEVOR die Installation beginnt
validate_installation_parameters


# ── System-Vorbereitung ──────────────────────────────────────────────────────
info "Initialisiere sudo-Sitzung…"
run_or_die sudo -v

info "Prüfe Docker…"
if ! check_command docker; then
  info "Docker wird installiert…"
  run_or_die curl -fsSL https://get.docker.com | sudo sh
else
  info "Docker vorhanden."
fi

if ! id -nG "$USER_NAME" | grep -qw docker; then
  info "Füge $USER_NAME zur Docker-Gruppe hinzu…"
  run_or_die sudo usermod -aG docker "$USER_NAME"
  warn "Bitte neu einloggen oder: sudo reboot"
  exit $EXIT_PERMISSION_DENIED
fi

info "Prüfe Docker-Compose Plugin…"
if ! docker compose version >/dev/null 2>&1; then
  run_or_die sudo apt update
  run_or_die sudo apt install -y docker-compose-plugin
fi

if [ -f "$REQUIREMENTS_FILE" ]; then
  info "Installiere Python-Abhängigkeiten…"
  run_or_die pip3 install --upgrade pip
  run_or_die pip3 install -r "$REQUIREMENTS_FILE"
fi

if [ ! -f "$SSH_KEY_PATH" ]; then
  info "Generiere neuen SSH-Key…"
  run_or_die ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N ""
fi

info "Setze SSH-Port ($SSH_PORT)…"
SSH_DROPIN="/etc/ssh/sshd_config.d/20-adlah-port.conf"
# Schreibe Port in Drop-In, nicht in die Hauptdatei, um Korruption zu vermeiden
CURRENT_PORT_LINE=$(sudo bash -lc "test -f '$SSH_DROPIN' && grep -E '^Port[[:space:]]+' '$SSH_DROPIN' | head -n1 || true")
if [[ "$CURRENT_PORT_LINE" != "Port $SSH_PORT" ]]; then
  run_or_die sudo mkdir -p /etc/ssh/sshd_config.d
  # Sicher schreiben via sudo tee; nur printf-Output wird gepiped
  run_or_die bash -lc "printf '%s\\n' 'Port $SSH_PORT' | sudo tee '$SSH_DROPIN' >/dev/null"
  # Konfiguration validieren, dann Dienst neustarten
  abort_if_fail sudo sshd -t
  run_or_die sudo systemctl restart ssh || sudo systemctl restart sshd
else
  note "SSH-Port bereits konfiguriert."
fi

# ── HIVE Installation ────────────────────────────────────────────────────────
if [[ $INSTALL_TYPE == "hive" ]]; then
  note "Kibana-Anmeldedaten konfiguriert."
  info "Redis wird lokal im Hive-Stack bereitgestellt."

  # Bestätigung
  if [[ "$AUTO_CONFIRM" != "yes" ]]; then
    read -rp "Installationsmodus HIVE. Fortfahren? (y/N): " confirm
    if [[ "${confirm,,}" != "y" && "${confirm,,}" != "yes" ]]; then
      info "Installation abgebrochen."
      exit $EXIT_QUIT
    fi
  else
    info "Automatische Bestätigung aktiviert - fahre mit Hive-Installation fort"
  fi

  TARGET_DIR="$HOME/hive"
  ensure_dir "$TARGET_DIR"
  ensure_dir "$TARGET_DIR/env"

  # RL-Agent-ENV
  info "Erstelle RL-Agent Konfiguration..."
  cat >"$TARGET_DIR/env/rl-agent.env" <<EOF
LOGLEVEL=INFO
WINDOW_SEC=300
TRANSFORM_DEST=features_madcat
HONEYPOD_NS=default
HONEYPOD_TTL_SEC=1800
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_CHANNEL=honeypod-map
REWARD_ALPHA=1.0
REWARD_BETA=0.05
CPU_WEIGHT=0.7
MEM_WEIGHT=0.3
ES_STARTUP_DELAY=20
ES_HOST=http://elasticsearch:9200
EOF

  # ADLAH ENV
  info "Erstelle ADLAH Konfiguration..."
  cat >"$ENV_FILE" <<EOF
ADLAH_TYPE=HIVE
ADLAH_USER=$KIBANA_USER
KIBANA_ENCRYPTION_KEY=$KIBANA_ENCRYPTION_KEY
EOF
  run_or_die cp "$ENV_FILE" "$TARGET_DIR/.env"

  info "Kopiere Hive-Dateien…"
  if ! rsync -a --no-perms --chown=lukas:lukas ./hive/ "$TARGET_DIR/"; then
    die "Fehler beim Kopieren der Hive-Dateien (Exit-Code: $?)"
  fi
  
  # Prüfe ob Kopieren erfolgreich war
  check_path_exists "$TARGET_DIR/docker-compose.yml" "Hive Docker Compose Konfiguration im Zielverzeichnis"

  info "Erzeuge htpasswd-Datei…"
  if ! check_command htpasswd; then
    run_or_die sudo apt install -y apache2-utils
  fi
  run_or_die mkdir -p "$TARGET_DIR/nginx"
  # Falls altes htpasswd versehentlich als Verzeichnis existiert
  cleanup_maybe_dir "$TARGET_DIR/nginx/htpasswd"
  run_or_die htpasswd -mbc "$TARGET_DIR/nginx/htpasswd" "$KIBANA_USER" "$KIBANA_PASSWORD"

  info "Generiere TLS-Zertifikat…"
  CERT_DIR="$TARGET_DIR/nginx/certs"
  ensure_dir "$CERT_DIR"
  # Alte Artefakte (Datei oder Verzeichnis) entfernen
  cleanup_maybe_dir "$CERT_DIR/selfsigned.key"
  cleanup_maybe_dir "$CERT_DIR/selfsigned.crt"
  run_or_die openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$CERT_DIR/selfsigned.key" \
      -out   "$CERT_DIR/selfsigned.crt" \
      -subj "/CN=localhost"

  # Prüfe ob Kibana-Konfiguration existiert
  if [[ -f "$TARGET_DIR/kibana/dist/kibana.yml" ]]; then
    sed -i "s|__ENCRYPTION_KEY__|$KIBANA_ENCRYPTION_KEY|g" "$TARGET_DIR/kibana/dist/kibana.yml" || warn "Kibana-Konfiguration konnte nicht aktualisiert werden"
  else
    warn "Kibana-Konfigurationsdatei nicht gefunden: $TARGET_DIR/kibana/dist/kibana.yml"
  fi

  info "Starte Hive-Stack…"
  run_or_die sudo systemctl enable docker
  run_or_die sudo systemctl start docker
  run_compose_stack "$TARGET_DIR"

  info "Hive ist bereit: http://<deine-ip>:64297"

# ── SENSOR Installation ──────────────────────────────────────────────────────
else # Dies deckt nur den 'sensor'-Fall ab, da der Typ validiert wurde
  note "Sensor-Konfiguration konfiguriert."
  # Interface-Validierung wurde bereits in validate_installation_parameters durchgeführt

  # Bestätigung
  if [[ "$AUTO_CONFIRM" != "yes" ]]; then
    read -rp "Installationsmodus SENSOR. Fortfahren? (y/N): " confirm
    if [[ "${confirm,,}" != "y" && "${confirm,,}" != "yes" ]]; then
      info "Installation abgebrochen."
      exit $EXIT_QUIT
    fi
  else
    info "Automatische Bestätigung aktiviert - fahre mit Sensor-Installation fort"
  fi

  MADCAT_IP=$(ip -4 addr show "$MADCAT_IF" \
              | awk '/inet / {print $2}' | cut -d/ -f1)
  info "MADCAT nutzt IP $MADCAT_IP"

  TARGET_DIR="$HOME/sensor"
  run_or_die mkdir -p "$TARGET_DIR"

  # ENV-Datei schreiben
  info "Erstelle Sensor Konfiguration..."
  cat >"$ENV_FILE" <<EOF
ADLAH_TYPE=SENSOR
HIVE_IP=$HIVE_IP
MADCAT_INTERFACE=$MADCAT_IF
MADCAT_IP=$MADCAT_IP
MGMT_INTERFACE=$MGMT_IF
EOF
  run_or_die cp "$ENV_FILE" "$TARGET_DIR/.env"

  info "Kopiere Sensor-Dateien..."
  if ! rsync -a --no-perms --chown=lukas:lukas sensor/ "$TARGET_DIR/"; then
    die "Fehler beim Kopieren der Sensor-Dateien (Exit-Code: $?)"
  fi
  
  # NEU: Sicherstellen, dass das Umleitungsskript ausführbar ist
  if [ -f "$TARGET_DIR/redirect_attacker.sh" ]; then
    chmod +x "$TARGET_DIR/redirect_attacker.sh"
    info "Umleitungsskript ausführbar gemacht."
  fi

  # Prüfe ob Kopieren erfolgreich war
  check_path_exists "$TARGET_DIR/docker-compose.yml" "Sensor Docker Compose Konfiguration im Zielverzeichnis"
  
  run_or_die sudo mkdir -p /var/log/madcat && sudo chown "$USER_NAME":"$USER_NAME" /var/log/madcat

  # Pfad-Fix für Run-Script
  MADCAT_RUN="$TARGET_DIR/madcat/scripts/run_madcat.sh"
  if [[ -f $MADCAT_RUN ]]; then
    info "Passe MADCAT Run-Script an..."
    # 1) Pfad-Fix & sudo raus
    run_or_die sed -i 's|/opt/madcat/data|/var/log/madcat|g; s/\bsudo\b //g' "$MADCAT_RUN"
    # 2) NEU → Interface-Parameter injizieren
    run_or_die sed -i -E 's|^(MADCAT_CMD="madcat )|\1-i ${MADCAT_INTERFACE} |' "$MADCAT_RUN"
    run_or_die chmod +x "$MADCAT_RUN"
  fi

  info "Installiere SSH-Server…"
  run_or_die sudo apt install -y openssh-server
  run_or_die sudo systemctl enable ssh
  run_or_die sudo systemctl start ssh

  info "Starte Sensor-Stack…"
  run_or_die sudo systemctl enable docker
  run_or_die sudo systemctl start docker
  run_compose_stack "$TARGET_DIR"

  if docker exec madcat ps aux | grep madcat | grep -v grep; then
    info "Sensor ist bereit. Jetzt deploy.sh auf dem Hive ausführen."
  else
    warn "MADCAT-Prozess läuft möglicherweise nicht korrekt"
  fi
fi

info "Installation erfolgreich abgeschlossen!"

