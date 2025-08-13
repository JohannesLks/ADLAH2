#!/usr/bin/env bash
# ——————————————————————————————————————————————————————————————————————————————
# ADLAH – Deploy-/Onboard-Skript  (Hive  ⇄  Sensor/Cluster)
# ——————————————————————————————————————————————————————————————————————————————


set -Eeuo pipefail
shopt -s inherit_errexit

###############################################################################
# Farben & Helfer
###############################################################################
C0='\e[0m'; C1='\e[36m'; C2='\e[32m'; C3='\e[33m'; C4='\e[31m'
info () { echo -e "${C2}[deploy]${C0} $*"; }
note () { echo -e "${C1}[deploy]${C0} $*"; }
warn () { echo -e "${C3}[deploy] $*${C0}"; }
die  () { echo -e "${C4}[deploy] $*${C0}" >&2; exit 1; }

###############################################################################
# Allgemeine Variablen
###############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$SCRIPT_DIR/k8s"
ENV_FILE="$HOME/.adlah_env"
CERT_DIR="$HOME/.adlah_certs"
FILEBEAT_CERT_DIR="$HOME/filebeat-certs"
HIVE_STACK="$HOME/hive"

K3S_DIR="$HOME/.adlah_k3s"                      # Ablage für Installer/Binary
K3S_VERSION="${K3S_VERSION:-v1.30.1+k3s1}"      # Gewünschte Version
K3S_INST="$K3S_DIR/install_k3s.sh"
K3S_BIN="$K3S_DIR/k3s"

SSH_PORTS=(${ADLAH_SSH_PORTS:-22})              # mehrere Ports möglich
SSH_OPT=${ADLAH_SSH_KEY:+-i "$ADLAH_SSH_KEY"}   # optionaler privater Key
SSH_PORT_CFG="${SSH_PORTS[0]}"
SSH_KEY_OPT=${ADLAH_SSH_KEY:+-i ${ADLAH_SSH_KEY}}

# SSH key permissions are now handled by the calling script (reinstall.sh)

###############################################################################
# SSH-Hostkey-Absicherung
###############################################################################
ensure_known_host() {
  local host="$1" port="${2:-22}"
  note "SSH-Hostkey für $host:$port wird geprüft…"
  ssh-keygen -R "[$host]:$port" &>/dev/null || true
  ssh-keyscan -p "$port" -H "$host" >> ~/.ssh/known_hosts 2>/dev/null || {
    warn "ssh-keyscan für $host:$port fehlgeschlagen."
  }
}

###############################################################################
# SSH- & SCP-Wrapper (mit Port-Failover)
###############################################################################
retry_ssh() {
  local remote="$1"; shift
  local host="${remote#*@}"
  local script="$*"

  for p in "${SSH_PORTS[@]}"; do
    ensure_known_host "$host" "$p"
    note "SSH  → $remote (Port $p)…"

    if ssh -tt -o BatchMode=yes -o ConnectTimeout=5 -p "$p" $SSH_OPT \
          "$remote" bash -s <<EOF; then
set -Eeuo pipefail
export PS4='+ [\$(date "+%H:%M:%S")] \$LINENO: '
exec 2> >(tee /tmp/remote-stderr.log >&2)
exec 1> >(tee /tmp/remote-stdout.log)
set -x
$script
exit 0
EOF
      return 0
    else
      warn "SSH-Befehl auf $remote schlug fehl"
    fi
  done

  die "SSH-Befehl konnte auf keinem Port erfolgreich ausgeführt werden."
}

retry_scp() {
  local -a srcs=("${@:1:$#-1}")
  local dest="${@: -1}"

  # Wenn Ziel **kein** ':' enthält ➟ lokaler Pfad ➟ direkt scp
  if [[ $dest != *:* ]]; then
    scp -o BatchMode=yes -o ConnectTimeout=5 "${srcs[@]}" "$dest"
    return
  fi

  local remote="${dest%%:*}"
  local host="${remote#*@}"
  for p in "${SSH_PORTS[@]}"; do
    ensure_known_host "$host" "$p"
    note "SCP  → $dest (Port $p)…"
    # Force correct permissions on the key right before use
    if [[ -n "${ADLAH_SSH_KEY-}" && -f "$ADLAH_SSH_KEY" ]]; then
        chmod 600 "$ADLAH_SSH_KEY"
    fi
    if scp -o BatchMode=yes -o ConnectTimeout=5 -P "$p" $SSH_OPT \
          "${srcs[@]}" "$dest"; then
      return 0
    fi
    warn "Port $p fehlgeschlagen."
  done
  die "SCP zu $dest nicht möglich."
}

###############################################################################
# Hive-Vorbereitung
###############################################################################
[[ -f $ENV_FILE ]] || die "$ENV_FILE fehlt (HIVE-VM?)"
grep -q 'ADLAH_TYPE=HIVE' "$ENV_FILE" || \
  die "Dieses Skript darf nur auf einer Hive-VM laufen!"

info "lokalen rl-agent stoppen (falls vorhanden)…"
docker compose -f "$HIVE_STACK/docker-compose.yml" rm -fs rl-agent &>/dev/null || true

# Bereinigung: k3s darf NICHT auf der Hive laufen
if systemctl is-active --quiet k3s; then
  warn "k3s läuft auf der Hive-VM - das sollte nicht sein! Stoppe es..."
  sudo systemctl stop k3s || true
  sudo systemctl disable k3s || true
fi

# Port 6443-Check nur für Cluster-Modus (wird später ausgeführt)

# CLI-Parsing (direkt nach den Funktionen, vor jeglicher Logik!)
MODE= CLUSTER_IP= CLUSTER_USER= GRAF_PWD= HONEYPOD_RANGE="10.2.0.0/16"
usage() { cat <<USAGE
Usage:
  $0 --cluster --ip <IP> --user <ssh-user> [--grafana-pass <PW>] [--honeypod-range <CIDR>]
  $0 --sensor  --ip <IP> --user <ssh-user>

Flags/Parameter:
  --cluster             Cluster-Modus (Hive → Cluster)
  --sensor              Sensor-Modus (Hive → Sensor)
  --ip <IP>             Ziel-IP der Cluster/Sensor-VM
  --user <ssh-user>     SSH-Benutzername für Ziel-VM
  --grafana-pass <PW>   (optional, Cluster) Passwort für Grafana-Admin
  --honeypod-range <CIDR> (optional, Cluster) Honeypod-IP-Range, z.B. 10.2.0.0/16 (Default: 10.2.0.0/16)
  -h, --help            Diese Hilfe anzeigen

Beispiele:
  $0 --cluster --ip 10.1.0.10 --user johannes --honeypod-range 10.2.0.0/16
  $0 --sensor --ip 10.1.0.20 --user johannes
USAGE
exit 0; }

eval set -- "$(getopt -o h --long help,cluster,sensor,ip:,user:,grafana-pass:,honeypod-range: -- "$@")"
while true; do
  case $1 in
    --cluster) MODE=CLUSTER;;
    --sensor)  MODE=SENSOR;;
    --ip)      CLUSTER_IP=$2; shift;;
    --user)    CLUSTER_USER=$2; shift;;
    --grafana-pass) GRAF_PWD=$2; shift;;
    --honeypod-range) HONEYPOD_RANGE=$2; shift;;
    -h|--help) usage ;;
    --) shift; break ;;
    *) usage ;;
  esac; shift
done

# ... ab hier erst die eigentliche Logik ...

[[ $MODE ]]        || usage

# Unterschiedliche Prompts je nach Modus
if [[ $MODE == SENSOR ]]; then
  [[ $CLUSTER_IP ]]  || read -rp "Sensor-IP: " CLUSTER_IP
  [[ $CLUSTER_USER ]]|| CLUSTER_USER="lukas"
else
  [[ $CLUSTER_IP ]]  || read -rp "Cluster-IP: " CLUSTER_IP
  [[ $CLUSTER_USER ]]|| CLUSTER_USER="lukas"
  [[ $MODE == CLUSTER && -z $GRAF_PWD ]] && GRAF_PWD=$(openssl rand -base64 16)
fi

info "Mode=$MODE  Host=$CLUSTER_IP  User=$CLUSTER_USER"

###############################################################################
# k3s-Installer + Binary (einmalig auf Hive laden)
###############################################################################
mkdir -p "$K3S_DIR"

if [[ ! -f $K3S_INST ]]; then
  info "lade k3s-Installer herunter…"
  curl -fSL https://get.k3s.io -o "$K3S_INST"
  chmod +x "$K3S_INST"
fi

if [[ ! -f $K3S_BIN ]]; then
  ARCH=$(uname -m)
  info "lade k3s-Binary $K3S_VERSION ($ARCH)…"
  curl -fSL \
    "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s" \
    -o "$K3S_BIN"
  chmod +x "$K3S_BIN"
fi

###############################################################################
# Zertifikate generieren (falls nicht vorhanden)
###############################################################################
mkdir -p "$CERT_DIR"
if [[ ! -f $CERT_DIR/logstash.crt || ! -f $CERT_DIR/logstash.key ]]; then
  info "erstelle self-signed Logstash-TLS-Zertifikat…"
  openssl req -nodes -x509 -sha512 -newkey rsa:4096 \
    -days 365 -keyout "$CERT_DIR/logstash.key" -out "$CERT_DIR/logstash.crt" \
    -subj "/C=DE/O=ADLAH" \
    -addext "subjectAltName = IP:$(hostname -I | awk '{print $1}')" >/dev/null
fi

###############################################################################
# SENSOR-MODE
###############################################################################
if [[ $MODE == SENSOR ]]; then
  mkdir -p "$FILEBEAT_CERT_DIR"
  
  # Prüfe ob die Zertifikate existieren
  if [[ ! -f "$CERT_DIR/logstash.crt" || ! -f "$CERT_DIR/logstash.key" ]]; then
    die "Zertifikate nicht gefunden in $CERT_DIR. Führe zuerst die Zertifikatsgenerierung aus."
  fi
  
  cp "$CERT_DIR"/logstash.{crt,key} "$FILEBEAT_CERT_DIR/"
  
  # Stelle sicher, dass die Zertifikate die richtigen Berechtigungen haben
  # Für SCP müssen die Dateien lesbar sein
  chmod 644 "$CERT_DIR/logstash.crt"
  chmod 644 "$CERT_DIR/logstash.key"
  
  # Zeige die aktuellen Berechtigungen für Debugging
  info "Zertifikatsberechtigungen:"
  ls -la "$CERT_DIR"/logstash.*
  
  # Erstelle das Verzeichnis auf dem Sensor mit korrekten Berechtigungen
  retry_ssh "$CLUSTER_USER@$CLUSTER_IP" "rm -rf ~/adlah_certs && mkdir -p ~/adlah_certs && ls -la ~/adlah_certs"
  
  # Kopiere die Zertifikate
  retry_scp "$CERT_DIR/logstash.crt" "$CERT_DIR/logstash.key" \
            "$CLUSTER_USER@$CLUSTER_IP:~/adlah_certs/"
  
  # Setze die korrekten Berechtigungen auf dem Sensor
  retry_ssh "$CLUSTER_USER@$CLUSTER_IP" "chmod 644 ~/adlah_certs/logstash.crt && chmod 600 ~/adlah_certs/logstash.key"
  
  info "Sensor-TLS-Onboarding abgeschlossen"
  exit 0
fi

###############################################################################
# CLUSTER-MODE
###############################################################################

# Stelle sicher, dass Port 6443 frei ist (nur für Cluster-Modus)
if sudo lsof -i :6443 &>/dev/null; then
  warn "Port 6443 ist belegt. Bereinige..."
  sudo fuser -k 6443/tcp || true
  sleep 2
fi

info "Grafana-Passwort: $GRAF_PWD"
HIVE_IP=$(hostname -I | awk '{print $1}')
export HIVE_IP
HIVE_IP_FOR_CLUSTER=${ADLAH_HIVE_IP_OVERRIDE:-$HIVE_IP}

if [[ -z $HIVE_IP_FOR_CLUSTER ]]; then
  die "HIVE_IP_FOR_CLUSTER konnte nicht ermittelt werden. Setzen Sie ggf. ADLAH_HIVE_IP_OVERRIDE."
fi
note "Hive-IP für Cluster-Kommunikation: $HIVE_IP_FOR_CLUSTER"

# Hostkey-Check auf allen freigegebenen SSH-Ports
for port in "${SSH_PORTS[@]}"; do ensure_known_host "$CLUSTER_IP" "$port"; done

# Zertifikat + k3s-Dateien auf Cluster-VM kopieren
retry_scp "$CERT_DIR/logstash.crt" "$CERT_DIR/logstash.key" "$CLUSTER_USER@$CLUSTER_IP:/tmp/"
retry_scp "$K3S_INST" "$K3S_BIN"            "$CLUSTER_USER@$CLUSTER_IP:/tmp/"

# Prepare honeypod-pool.yaml for later copying
export HONEYPOD_RANGE
envsubst '$HONEYPOD_RANGE' < "$K8S_DIR/honeypod-pool.yaml" > /tmp/honeypod-pool.yaml

###############################################################################
# COMPLETE KUBERNETES CLEANUP - Clean reinstall
###############################################################################
info "🧹 Führe komplette Kubernetes-Bereinigung für saubere Neuinstallation durch..."

# First, try to connect and clean up everything on the cluster
cleanup_ok=0
for p in "${SSH_PORTS[@]}"; do
  ensure_known_host "$CLUSTER_IP" "$p"
  note "Cleanup → $CLUSTER_USER@$CLUSTER_IP (Port $p)…"
  
  if ssh -T -o BatchMode=yes -o ConnectTimeout=5 -p "$p" $SSH_OPT \
        "$CLUSTER_USER@$CLUSTER_IP" bash -s <<'CLEANUP_EOF'
set -Eeuo pipefail
log() { echo -e "\e[34m[cleanup] $*\e[0m"; }

log "🧹 Starte komplette Kubernetes-Bereinigung..."

# Stop k3s service
log "Stoppe k3s Service..."
sudo systemctl stop k3s || true
sudo systemctl disable k3s || true

# Kill any remaining k3s processes
log "Beende alle k3s Prozesse..."
sudo pkill -f k3s || true
sudo pkill -f containerd || true

# Clean up k3s data directories
log "Lösche k3s Datenverzeichnisse..."

# Zuerst alle Pods und Container stoppen
log "Stoppe alle Kubernetes-Pods..."
if command -v kubectl >/dev/null 2>&1; then
  kubectl delete pods --all --force --grace-period=0 2>/dev/null || true
  kubectl delete deployments --all --force --grace-period=0 2>/dev/null || true
  kubectl delete daemonsets --all --force --grace-period=0 2>/dev/null || true
fi

# Warte kurz, damit die Pods sich beenden können
sleep 5

# Dann die Verzeichnisse löschen
sudo rm -rf /var/lib/rancher/k3s || true
sudo rm -rf /etc/rancher/k3s || true

# Kubelet-Verzeichnisse vorsichtig löschen (mit umount falls nötig)
log "Bereinige kubelet-Verzeichnisse..."
if mountpoint -q /var/lib/kubelet/pods 2>/dev/null; then
  sudo umount /var/lib/kubelet/pods/*/volumes/* 2>/dev/null || true
fi
sudo rm -rf /var/lib/kubelet || true
sudo rm -rf /var/lib/cni || true
sudo rm -rf /var/lib/calico || true
sudo rm -rf /opt/cni || true

# Clean up network interfaces and routes
log "Bereinige Netzwerk-Interfaces..."
sudo ip link delete cni0 2>/dev/null || true
sudo ip link delete flannel.1 2>/dev/null || true
sudo ip link delete cali+ 2>/dev/null || true
sudo ip route del 10.42.0.0/16 2>/dev/null || true
sudo ip route del 10.43.0.0/16 2>/dev/null || true

# Clean up iptables rules
log "Bereinige iptables Regeln..."
sudo iptables -t nat -F || true
sudo iptables -t mangle -F || true
sudo iptables -F || true
sudo iptables -X || true

# Clean up Docker/containerd
log "Bereinige Container-Runtime..."
sudo systemctl stop containerd || true
sudo systemctl disable containerd || true
sudo rm -rf /var/lib/containerd || true

# Clean up any remaining pods/containers
log "Beende alle verbleibenden Container..."
sudo docker stop $(sudo docker ps -aq) 2>/dev/null || true
sudo docker rm $(sudo docker ps -aq) 2>/dev/null || true

# Clean up systemd services
log "Bereinige Systemd Services..."
sudo systemctl reset-failed || true

# Clean up any remaining files
log "Bereinige verbleibende Dateien..."
sudo rm -rf /tmp/k3s* || true
sudo rm -rf /tmp/calico* || true
sudo rm -rf /tmp/metallb* || true

# Clean up user directories
log "Bereinige Benutzerverzeichnisse..."
rm -rf ~/.kube || true
rm -rf ~/.config/helm || true

log " Kubernetes-Bereinigung abgeschlossen"
CLEANUP_EOF
  then
    cleanup_ok=1
    break
  else
    warn "  Cleanup auf $CLUSTER_USER@$CLUSTER_IP schlug fehl"
  fi
done

if [[ $cleanup_ok -ne 1 ]]; then
  warn "  Cleanup fehlgeschlagen, aber fahre mit Installation fort..."
fi

# Copy all required files AFTER cleanup
note "Übertrage alle benötigten Dateien nach der Bereinigung…"
retry_scp "$K3S_INST" "$K3S_BIN" "$CLUSTER_USER@$CLUSTER_IP:/tmp/"
retry_scp "$K8S_DIR/calico.yaml" "$CLUSTER_USER@$CLUSTER_IP:/tmp/calico.yaml"
retry_scp "/tmp/honeypod-pool.yaml" "$CLUSTER_USER@$CLUSTER_IP:/tmp/honeypod-pool.yaml"
note "Übertrage Redis-Manifeste..."
retry_scp "$K8S_DIR/redis-pod.yaml" "$K8S_DIR/redis-service.yaml" "$CLUSTER_USER@$CLUSTER_IP:/tmp/"
note "Übertrage Orchestrator-Dateien..."
retry_scp -r "$SCRIPT_DIR/orchestrator" "$CLUSTER_USER@$CLUSTER_IP:/tmp/"
 
 ###############################################################################
# Remote-Bootstrap-Skript (offline)
###############################################################################
TMP_SCRIPT=$(mktemp)
cat > "$TMP_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

log() { echo -e "\e[34m[remote] $*\e[0m"; }

trap 'ec=$?; cmd=$BASH_COMMAND;
      echo -e "\e[31m[remote] Fehler in Zeile $LINENO: »$cmd« (Exit $ec)\e[0m" >&2' ERR

exec 2> >(tee /tmp/bootstrap.log >&2)
set -x

log "Starte Cluster-Bootstrap…"

log "Installiere benötigte Pakete (fuser, iptables, docker)..."
sudo apt-get update || true
sudo apt-get remove -y containerd.io || true
sudo apt-get install -y psmisc iptables docker.io

# Fix für non-interactive shells: Notwendige Umgebungsvariablen für systemd/dbus setzen
if [[ -z "${DBUS_SESSION_BUS_ADDRESS-}" ]]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"
fi

if [[ -z "${XDG_RUNTIME_DIR-}" ]]; then
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi

#############################################################################
# -1) Vorherige k3s-Prozesse und blockierende Ports bereinigen
#############################################################################
log "Bereinige eventuelle Reste von vorherigen Läufen..."
sudo systemctl stop k8s-api-tunnel.service || true
sudo fuser -k 6443/tcp || true
# Warte einen Moment, um sicherzustellen, dass der Port freigegeben ist
sleep 2

#############################################################################
# 0) Kernel-Parameter für Netfilter / Forwarding aktivieren
#############################################################################
sudo modprobe br_netfilter
sudo sh -c 'echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables'
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

#############################################################################
# 1) k3s (in /usr/local/bin) offline installieren
#############################################################################
# Prüfe zuerst, ob das k3s-Binary existiert, und installiere es bei Bedarf.
if ! command -v k3s >/dev/null; then
  log "k3s-Binary nicht gefunden, installiere..."
  if [[ -f /tmp/k3s ]]; then
    sudo cp /tmp/k3s /usr/local/bin/k3s
    sudo chmod +x /usr/local/bin/k3s
  else
    log "k3s-Binary nicht in /tmp gefunden. Breche ab."
    exit 1
  fi
else
  log "k3s-Binary bereits vorhanden."
fi

# Prüfe separat, ob die Kubeconfig-Datei existiert. Wenn nicht, führe den
# k3s-Installer aus, um die Konfiguration und den Systemd-Service zu erstellen.
if [ -f /etc/rancher/k3s/k3s.yaml ]; then
  log "k3s.yaml existiert bereits."
  
  # Prüfe, ob die k3s-Konfiguration die richtige TLS-SAN enthält
  if [ -f /etc/rancher/k3s/config.yaml ] && grep -q "127.0.0.1" /etc/rancher/k3s/config.yaml; then
    log "k3s-Konfiguration enthält bereits 127.0.0.1 als TLS-SAN."
  else
          log "k3s-Konfiguration muss aktualisiert werden (TLS-SAN für 127.0.0.1 fehlt)."
    
    # Erstelle oder aktualisiere die k3s-Konfiguration
    sudo mkdir -p /etc/rancher/k3s
    cat <<K3SCONFIG | sudo tee /etc/rancher/k3s/config.yaml > /dev/null
tls-san:
  - $CLUSTER_IP
  - 127.0.0.1
  - host.docker.internal
disable:
  - traefik
write-kubeconfig-mode: "0644"
K3SCONFIG
    
    log "Lösche alte Zertifikate und starte k3s neu..."
    sudo rm -rf /var/lib/rancher/k3s/server/tls/*.crt /var/lib/rancher/k3s/server/tls/*.key
    sudo systemctl restart k3s.service
    
    log "Warte 15 Sekunden, damit k3s neue Zertifikate generiert..."
    sleep 15
  fi
else
  log "k3s.yaml nicht gefunden, installiere k3s..."
  log "TLS-SAN IP: $CLUSTER_IP"
  sudo env INSTALL_K3S_SKIP_DOWNLOAD=true \
       INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable traefik --tls-san $CLUSTER_IP --tls-san 127.0.0.1 --tls-san host.docker.internal --write-kubeconfig-mode 644" \
       /tmp/install_k3s.sh || { journalctl -xeu k3s.service; exit 1; }
fi

# Stelle sicher, dass k3s läuft und starte es bei Bedarf
if ! sudo systemctl is-active --quiet k3s.service; then
  log "k3s-Dienst ist nicht aktiv. Starte ihn..."
  sudo systemctl start k3s.service || {
          log "k3s konnte nicht gestartet werden. Prüfe Logs..."
    sudo journalctl -n 50 --no-pager -u k3s.service
    exit 1
  }
fi

# Warte kurz, damit k3s vollständig hochfährt
sleep 5

#############################################################################
# 2) Kubeconfig einrichten
#############################################################################
log "Konfiguriere Kubeconfig"
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config || true
sudo chown "$USER:$USER" ~/.kube/config
export KUBECONFIG=~/.kube/config

log "Warte auf Kubernetes-API-Server (max. 5 Minuten)..."
for i in {1..60}; do
  # 'kubectl version' ist ein leichter Check, um die API-Verfügbarkeit zu prüfen
  if kubectl version &>/dev/null; then
    log "Kubernetes-API ist bereit."
    break
  fi
  log "... API noch nicht bereit, warte 5 Sekunden ($i/60)"
  sleep 5
done

# Finale Prüfung, ob die API erreichbar ist, sonst Abbruch
if ! kubectl version &>/dev/null; then
  log "Kubernetes-API nach 5 Minuten nicht erreichbar. Überprüfe k3s-Logs mit 'sudo journalctl -u k3s'."
  exit 1
fi

#############################################################################
# 3a) Calico CNI installieren und konfigurieren
#############################################################################
log "Installiere Calico CNI..."
sudo kubectl apply -f /tmp/calico.yaml

log "Warte auf Calico-Rollout (kann einige Minuten dauern)..."
# Warte bis der DaemonSet auf allen Nodes ausgerollt ist.
if ! sudo kubectl -n kube-system rollout status ds/calico-node --timeout=240s; then
    log "Calico-Rollout fehlgeschlagen. Prüfe Pods:"
    sudo kubectl -n kube-system get pods -o wide
    exit 1
fi
log "Calico ist bereit."

log "Konfiguriere Calico IP-Pools..."
sudo kubectl apply -f /tmp/honeypod-pool.yaml
log "Deaktiviere den Standard-IP-Pool..."
sudo kubectl patch ippool default-ipv4-ippool --type merge -p '{"spec": {"disabled": true}}'

log "Erstelle Honeypod-Namespace für saubere Netzwerk-Trennung..."
sudo kubectl create namespace honeypod --dry-run=client -o yaml | sudo kubectl apply -f -

#############################################################################
# 3c) Redis Pod & Service installieren
#############################################################################
log "Installiere Redis..."
sudo kubectl apply -f /tmp/redis-pod.yaml
sudo kubectl apply -f /tmp/redis-service.yaml

log "Warte auf Redis-Pod..."
if ! sudo kubectl wait --for=condition=ready pod/redis -n honeypod --timeout=120s; then
 log "Redis-Pod nicht bereit. Prüfe Pods:"
 sudo kubectl get pods -n honeypod -l name=redis
 exit 1
fi
log "Redis ist bereit."

#############################################################################
# 3d) Honeypot Orchestrator installieren
#############################################################################
log "Installiere Honeypot Orchestrator..."
if [ -d "/tmp/orchestrator" ]; then
  log "Baue Orchestrator Docker-Image..."
  sudo docker build -t honeypot-orchestrator:latest /tmp/orchestrator
  
  log "Importiere Orchestrator-Image in k3s..."
  sudo docker save honeypot-orchestrator:latest | sudo k3s ctr images import -

  log "Wende Orchestrator Kubernetes-Konfiguration an..."
  sudo kubectl apply -f /tmp/orchestrator/rbac.yaml
  sudo kubectl apply -f /tmp/orchestrator/deployment.yaml
  
  log "Warte auf den Rollout des Orchestrators..."
  if ! sudo kubectl rollout status deployment/honeypot-orchestrator --timeout=120s; then
    log "Orchestrator-Rollout fehlgeschlagen. Prüfe Pods:"
    sudo kubectl get pods -l app=honeypot-orchestrator
    exit 1
  fi
  log "Honeypot Orchestrator ist bereit."
else
  log "Orchestrator-Verzeichnis /tmp/orchestrator nicht gefunden. Überspringe."
fi
 
 #############################################################################
 # 3c) MetalLB LoadBalancer installieren und konfigurieren
#############################################################################
log "Bereinige alte Pods um Ressourcen freizugeben..."
sudo kubectl delete pods --all-namespaces --field-selector=status.phase=Pending --ignore-not-found=true || true
sudo kubectl delete pods --all-namespaces --field-selector=status.phase=Failed --ignore-not-found=true || true

log "Prüfe verfügbare Ressourcen..."
sudo kubectl top nodes || true
sudo kubectl get nodes -o wide

# MetalLB wird übersprungen
log "Verwende NodePort-Services für Honeypods..."
SKIP_METALLB=true

# Honeypods werden per hostPort verfügbar gemacht
log "Traffic-Routing erfolgt über iptables auf dem Sensor"

#############################################################################
# 3b) Prometheus-Stack für Kubernetes-Metriken installieren
#############################################################################
# Wir verwenden kube-prometheus-stack (Prometheus-Operator, Exporter, Dashboards)
log "Installiere/aktualisiere Prometheus-Stack (kube-prometheus-stack)…"
# Helm installieren, falls nicht vorhanden
if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || true
helm repo update

#
# ---------- Pending-Release-Cleaner ----------------------------------------
#
clean_pending() {
  local rel=$1 ns=$2
  if helm status "$rel" -n "$ns" -o json | jq -e '.info.status | test("pending")' &>/dev/null; then
    log " Release '$rel' in Namespace '$ns' ist im 'pending'-Status. Versuche Rollback/Löschen..."
    
    # Finde die letzte erfolgreiche Revision
    local last_ok=$(helm history "$rel" -n "$ns" -o json | \
                    jq '[.[] | select(.status | test("deployed"))][-1].revision // 0')

    if [[ "$last_ok" -gt 0 ]]; then
      log "↩️  Rollback für '$rel' auf Revision $last_ok"
      helm rollback "$rel" "$last_ok" -n "$ns" --wait --cleanup-on-fail || \
        log "💣 Rollback fehlgeschlagen, versuche Deinstallation..." && helm uninstall "$rel" -n "$ns" || true
    else
      log "🗑  Keine erfolgreiche Revision für '$rel' gefunden – deinstalliere."
      helm uninstall "$rel" -n "$ns" || true
    fi
  fi
}

clean_pending prom monitoring

#
# ---------- Ende Pending-Release-Cleaner -----------------------------------
#
#############################################################################
# ⛏️  Bereinige alte honeypod-Pods/Deployments (CrashLoop / Pending Blocker)
#############################################################################
log "Bereinige alte honeypod-Deployments & Pods (CrashLoop/Pending)…"

# Sicherstellen, dass alle alten Honeypods mit Label weg sind
kubectl delete deployment,pod -n default -l app=honeypod --ignore-not-found=true --force --grace-period=0 || true

# Überspringe Prometheus/Grafana Installation (verursacht Timeouts)
log "Überspringe Prometheus/Grafana Installation für schnellere Bereitstellung..."
log "Grafana kann später manuell installiert werden falls benötigt."

# Prometheus-Service-Warteschleife übersprungen (Service nicht installiert)

#############################################################################
# 3d2) Zweites Interface für Honeypod-Netzwerk (dynamisch)
#############################################################################
log "Konfiguriere zweites Interface für Honeypod-Netzwerk (${HONEYPOD_RANGE})…"

HONEYPOD_IF="ens5"
HONEYPOD_NET="${HONEYPOD_RANGE}"
# Berechne Gateway-IP aus der CIDR (erste nutzbare IP)
HONEYPOD_GW=$(echo "${HONEYPOD_RANGE}" | sed 's|/.*||' | sed 's|\.[0-9]*$|.1|')

# Prüfe, ob das Interface existiert
if ip link show $HONEYPOD_IF >/dev/null 2>&1; then
    log " Interface $HONEYPOD_IF gefunden"
    # IP zuweisen, falls nicht vorhanden (mit korrekter Subnet-Mask)
    HONEYPOD_MASK=$(echo "${HONEYPOD_RANGE}" | sed 's|.*/||')
    if ! ip addr show $HONEYPOD_IF | grep -q "$HONEYPOD_GW"; then
        sudo ip addr add $HONEYPOD_GW/$HONEYPOD_MASK dev $HONEYPOD_IF
        log " IP $HONEYPOD_GW/$HONEYPOD_MASK zu $HONEYPOD_IF hinzugefügt"
    fi
    sudo ip link set $HONEYPOD_IF up
else
    log " Interface $HONEYPOD_IF nicht gefunden! Bitte prüfen."
    exit 1
fi

# IP-Forwarding aktivieren
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

log " Honeypod-Interface $HONEYPOD_IF ($HONEYPOD_GW/$HONEYPOD_MASK) bereit"

#############################################################################
# 3e) Honeypod Filebeat Config & Zertifikat-Secret
#############################################################################
log "Erzeuge ConfigMap filebeat-honeypod & Secret filebeat-certs (idempotent)…"

cat <<CM >/tmp/filebeat-honeypod.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /home/cowrie/log/*.log
      - /home/cowrie/log/*.json
    fields:
      src_ip: \${SRC_IP}
    json.keys_under_root: true
    json.add_error_key: true

output.logstash:
  hosts: ["${HIVE_IP}:5044"]
  ssl.enabled: false
CM


# HIVE_IP_FOR_CLUSTER wird für das Erzeugen der ConfigMap benötigt
export HIVE_IP_FOR_CLUSTER

# Erstelle Honeypod-Namespace für saubere Trennung
log "Erstelle Honeypod-Namespace für saubere Netzwerk-Trennung..."
kubectl create namespace honeypod --dry-run=client -o yaml | kubectl apply -f -

# Vorhandene Ressourcen löschen und neu anlegen, um Fehler zu beheben
log "Lösche alte Honeypod-Ressourcen (ConfigMap, Secret)…"
kubectl -n honeypod delete configmap filebeat-honeypod --ignore-not-found=true
kubectl -n honeypod delete secret filebeat-certs --ignore-not-found=true

log "Erzeuge ConfigMap filebeat-honeypod & Secret filebeat-certs im honeypod-Namespace…"

# Ersetze die Variable in der temporären Datei
envsubst '$HIVE_IP_FOR_CLUSTER' < /tmp/filebeat-honeypod.yml > /tmp/filebeat-honeypod.yml.tmp
mv /tmp/filebeat-honeypod.yml.tmp /tmp/filebeat-honeypod.yml

# ConfigMap aus der verarbeiteten Datei erstellen (im honeypod-Namespace)
kubectl -n honeypod create configmap filebeat-honeypod \
  --from-file=filebeat.yml=/tmp/filebeat-honeypod.yml \
  --dry-run=client -o yaml | kubectl apply -f -

# Secret für Filebeat-Certs erstellen (CA + Key) im honeypod-Namespace
kubectl -n honeypod create secret generic filebeat-certs \
  --from-file=/tmp/logstash.crt \
  --from-file=/tmp/logstash.key \
  --dry-run=client -o yaml | kubectl apply -f -

rm -f /tmp/filebeat-honeypod.yml
rm -f /tmp/filebeat-honeypod.yml.tmp

EOF

# Execute the remote bootstrap script
remote_ok=0
for p in "${SSH_PORTS[@]}"; do
  ensure_known_host "$CLUSTER_IP" "$p"
  note "SSH  → $CLUSTER_USER@$CLUSTER_IP (Port $p)…"
  
  # Export all required variables so they are available to the remote shell
  if ssh -T -o BatchMode=yes -o ConnectTimeout=5 -p "$p" $SSH_OPT \
        "$CLUSTER_USER@$CLUSTER_IP" env \
        "CLUSTER_IP=$CLUSTER_IP" \
        "GRAF_PWD=$GRAF_PWD" \
        "HIVE_IP=$HIVE_IP" \
        "HIVE_IP_FOR_CLUSTER=$HIVE_IP_FOR_CLUSTER" \
        "HONEYPOD_RANGE=$HONEYPOD_RANGE" \
        "SKIP_METALLB=${SKIP_METALLB:-false}" \
        "MODE=$MODE" \
        "CLUSTER_USER=$CLUSTER_USER" \
        "SENSOR_IP=$CLUSTER_IP" \
        "SENSOR_USER=$CLUSTER_USER" \
        "SENSOR_SSH_KEY=/app/secrets/id_rsa" \
        bash -s < "$TMP_SCRIPT"; then
    remote_ok=1
    break
  else
    warn "  SSH-Befehl auf $CLUSTER_USER@$CLUSTER_IP schlug fehl"
  fi
done

if [[ $remote_ok -ne 1 ]]; then
  die " Remote-Bootstrap auf $CLUSTER_IP fehlgeschlagen. Abbruch."
fi

# Ensure target directory exists and is writable, then copy kubeconfig from cluster to hive
# If directory exists and we can't write to it, we need sudo to fix it
if [[ -d "$HIVE_STACK/cluster_kubeconfig" ]]; then
  if [[ ! -w "$HIVE_STACK/cluster_kubeconfig" ]]; then
    warn "cluster_kubeconfig existiert, aber ist nicht schreibbar. Versuche mit sudo zu löschen..."
    sudo rm -rf "$HIVE_STACK/cluster_kubeconfig" || die "Kann cluster_kubeconfig nicht löschen. Bitte manuell mit 'sudo rm -rf $HIVE_STACK/cluster_kubeconfig' löschen."
  fi
fi

mkdir -p "$HIVE_STACK/cluster_kubeconfig"

# Explicitly remove the target to ensure it's created as a file
# rm -rf "$HIVE_STACK/cluster_kubeconfig/config_host" # This was causing the path to be a directory

# Get Kubeconfig
info "Fetching Kubeconfig from cluster..."

kubeconfig_ok=0
for p in "${SSH_PORTS[@]}"; do
  ensure_known_host "$CLUSTER_IP" "$p"
  note "Fetching kubeconfig → $CLUSTER_USER@$CLUSTER_IP (Port $p)…"
  # Use ssh+cat for robust file download, avoiding scp directory ambiguity
  if ssh -o BatchMode=yes -o ConnectTimeout=5 -p "$p" $SSH_OPT \
        "$CLUSTER_USER@$CLUSTER_IP" "cat /etc/rancher/k3s/k3s.yaml" > "$HIVE_STACK/cluster_kubeconfig/config_host"; then
    # Check if the downloaded file is not empty
    if [[ -s "$HIVE_STACK/cluster_kubeconfig/config_host" ]]; then
        kubeconfig_ok=1
        info "Kubeconfig erfolgreich von Port $p heruntergeladen."
        break
    else
        warn "  Kubeconfig file downloaded from port $p is empty."
        rm -f "$HIVE_STACK/cluster_kubeconfig/config_host"
    fi
  else
    warn "  Connection for kubeconfig download on port $p failed."
  fi
done

if [[ $kubeconfig_ok -ne 1 ]]; then
  die " Could not download kubeconfig from any port."
fi

# Wenn das Skript interaktiv in einem Terminal läuft (nicht in CI/CD),
# passe die Kubeconfig an, um den lokalen SSH-Tunnel zu verwenden.
if [[ -t 1 ]]; then
  info "Passe /etc/hosts und Kubeconfig für 'host.docker.internal' an..."
  # host.docker.internal zu /etc/hosts hinzufügen, falls nicht vorhanden
  if ! grep -q "host.docker.internal" /etc/hosts; then
    echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts >/dev/null
  fi

  info "Interaktive Ausführung erkannt. Passe Kubeconfig für lokalen SSH-Tunnel an..."
  sed -i -E "s|(server: https://)[^:]+(:6443)|\1host.docker.internal\2|" "$HIVE_STACK/cluster_kubeconfig/config_host"
fi

# Clean up temporary script
rm -f "$TMP_SCRIPT"

NODE_PORT=30000

# ------------------- rl-agent Deployment (jetzt für alle Modi) -------------------
info "Deploye rl-agent auf dem Hive (lokal)…"
(
  # Umgebungsvariablen für den Agenten setzen
  sudo mkdir -p "$HIVE_STACK/env" "$HIVE_STACK/secrets"
  sudo chown -R "${SUDO_USER:-$USER}:${SUDO_USER:-$USER}" "$HIVE_STACK/env" "$HIVE_STACK/secrets"

  # Gewährleiste Schreibrechte für aktuellen Nutzer BEVOR Dateien kopiert werden
  chown -R "${SUDO_USER:-$USER}:${SUDO_USER:-$USER}" "$HIVE_STACK/env" "$HIVE_STACK/secrets" 2>/dev/null || true

  # SSH-Key für den Sensor-Zugriff kopieren
  SSH_KEY_TO_USE="${ADLAH_SSH_KEY:-$HOME/.ssh/id_rsa}"
  if [[ -f "$SSH_KEY_TO_USE" ]]; then
    # Lösche alte Datei, falls sie von vorherigen sudo-Läufen root-owned ist
    rm -f "$HIVE_STACK/secrets/id_rsa" 2>/dev/null || sudo rm -f "$HIVE_STACK/secrets/id_rsa" || true
    cp "$SSH_KEY_TO_USE" "$HIVE_STACK/secrets/id_rsa"
    chmod 600 "$HIVE_STACK/secrets/id_rsa"
  else
    warn "SSH-Key $SSH_KEY_TO_USE nicht gefunden. Sensor-Umleitung wird fehlschlagen."
  fi

  cat > "$HIVE_STACK/env/rl-agent.env" <<EOF
ES_HOST=http://elasticsearch:9200
LOG_SOURCE=es
ES_LOG_INDEX=madcat-*
HONEYPOD_NS=honeypod
HONEYPOD_TTL_SEC=1800
HIVE_IP=$(hostname -I | awk '{print $1}')
# Cluster-spezifische Variablen nur im Cluster-Modus hinzufügen
EOF

  if [[ "$MODE" == "CLUSTER" ]]; then
    cat >> "$HIVE_STACK/env/rl-agent.env" <<EOF
CLUSTER_SSH_HOST=$CLUSTER_IP
CLUSTER_SSH_USER=$CLUSTER_USER
K8S_API_SERVER=https://$CLUSTER_IP:6443
K8S_TOKEN_FILE=/secrets/cluster_token
K8S_CA_FILE=/secrets/cluster_ca.crt
EOF
  elif [[ "$MODE" == "SENSOR" ]]; then
    # Im Sensor-Modus wird keine SSH-Verbindung mehr benötigt,
    # da die Kommunikation über Redis läuft.
    # Die REDIS_URL wird vom redirector-agent direkt verwendet.
    cat >> "$HIVE_STACK/env/rl-agent.env" <<EOF
# Configuration for Redis-based redirection (no SSH needed)
EOF
  fi
  
  # Fix permissions after creating the env file
  chown "${SUDO_USER:-$USER}:${SUDO_USER:-$USER}" "$HIVE_STACK/env/rl-agent.env" 2>/dev/null || true

  info "Docker-Compose → rl-agent starten…"
  docker compose -f "$HIVE_STACK/docker-compose.yml" up -d rl-agent
)

###############################################################################
# Systemd-User-Tunnels (Grafana & K8s-API)
###############################################################################
mkdir -p "$HOME/.config/systemd/user"
loginctl enable-linger "$(whoami)" &>/dev/null || true

# Stoppe existierende Tunnel, falls vorhanden
info "Stoppe existierende SSH-Tunnel..."
systemctl --user stop grafana-tunnel.service k8s-api-tunnel.service &>/dev/null || true

# Warte kurz, damit die Ports freigegeben werden
sleep 2

# Prüfe nochmals, ob Port 6443 frei ist
if lsof -i :6443 &>/dev/null; then
  warn "Port 6443 ist immer noch belegt nach Tunnel-Stop. Erzwinge Freigabe..."
  fuser -k 6443/tcp &>/dev/null || true
  sleep 2
fi

create_tunnel() { local name=$1 portmap=$2
  cat > "$HOME/.config/systemd/user/$name.service" <<SVC
[Unit]
Description=ADLAH SSH-Tunnel ($name)
After=network-online.target

[Service]
ExecStart=/usr/bin/ssh -g -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 \
         -N -L ${portmap} -p ${SSH_PORT_CFG} ${SSH_KEY_OPT} ${CLUSTER_USER}@${CLUSTER_IP}
Restart=always
RestartSec=5
StartLimitBurst=3
StartLimitIntervalSec=30

[Install]
WantedBy=default.target
SVC
}

create_tunnel grafana-tunnel "3000:localhost:30000"

# Grafana-Tunnel bleibt unverändert
# K8s-API via Gateway-Adresse erreichbar machen
create_tunnel k8s-api-tunnel "0.0.0.0:6443:localhost:6443"

systemctl --user daemon-reload
systemctl --user enable --now grafana-tunnel.service k8s-api-tunnel.service

# 1. kubectl installieren (stable channel)
# kubectl is now installed by reinstall.sh

# 2. Kubeconfig dauerhaft setzen
echo 'export KUBECONFIG=$HOME/hive/cluster_kubeconfig/config_host' >> ~/.bashrc
source ~/.bashrc

# 3. Schneller Health-Check der API
if kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" get nodes &>/dev/null; then
  info "K8s-API erreichbar "
else
  warn "  K8s-API nicht erreichbar – bitte Firewall/SSH-Tunnel prüfen"
fi

info "Cluster-Onboarding fertig "
info "Grafana lokal: http://localhost:3000"

# After setting KUBECONFIG
info "Warte auf K8s-API-Tunnel..."
TUNNEL_OK=0
for i in {1..30}; do
  if kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" get nodes &>/dev/null; then
    info "K8s-API-Tunnel ist aktiv "
    TUNNEL_OK=1
    break
  fi
  
  # Prüfe ob der Tunnel-Service läuft
  if ! systemctl --user is-active --quiet k8s-api-tunnel.service; then
    warn "K8s-API-Tunnel-Service ist nicht aktiv. Versuche Neustart..."
    systemctl --user restart k8s-api-tunnel.service || true
    sleep 5
  fi
  
  warn "Warte auf K8s-API-Tunnel... Versuch $i"
  sleep 2
done

if [[ ${TUNNEL_OK:-0} -ne 1 ]]; then
  warn " K8s-API-Tunnel konnte nach 30 Versuchen nicht aufgebaut werden."
  
  # Diagnose-Informationen sammeln
  warn "Tunnel-Service Status:"
  systemctl --user status k8s-api-tunnel.service --no-pager || true
  
  warn "Port 6443 Belegung:"
  lsof -i :6443 || true
  
  warn "Versuche kubectl direkt:"
  kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" get nodes || true
  
  die  "Abbruch wegen fehlendem K8s-API-Tunnel. Bitte SSH-Konfiguration prüfen."
fi
info "Bereinige alte honeypod-Deployments & Pods (finale Prüfung nach RL-Agent-Start)…"

# Warmhalte‐Pool bestehen lassen – Deployment NICHT löschen (benötigt für schnelle Pod-Übernahme)

# Dann lösche alle Pods mit dem honeypod Label im honeypod-Namespace
kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" delete pod -n honeypod -l app=honeypod --ignore-not-found=true --grace-period=0 --force || true

# Warte kurz
sleep 2

# Falls immer noch Pods im Terminating-Status sind, lösche sie mit einem Patch
info "Entferne hartnäckige Terminating-Pods..."
for pod in $(kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" get pods -n honeypod -l app=honeypod -o name 2>/dev/null | cut -d/ -f2); do
  kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" patch pod "$pod" -n honeypod -p '{"metadata":{"finalizers":null}}' --type=merge 2>/dev/null || true
done

# Optional warten bis alles weg ist (mit kürzerem Timeout)
for i in {1..10}; do
  if ! kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" get pods -n honeypod -l app=honeypod 2>/dev/null | grep -q honeypod; then
    info "Honeypod-Pods final entfernt."
    break
  fi
  warn "Honeypod-Pods noch vorhanden… Warte ($i)"
  sleep 1
done

# Wenn nach 10 Sekunden immer noch Pods da sind, ist das kein kritischer Fehler
if kubectl --kubeconfig="$HIVE_STACK/cluster_kubeconfig/config_host" get pods -n honeypod -l app=honeypod 2>/dev/null | grep -q honeypod; then
  warn "Einige Honeypod-Pods sind noch im Terminating-Status. Das ist normal und wird sich selbst lösen."
fi

#############################################################################
# 3e) Honeypod Warm-Up Pool (Pre-warmed Pods)
#############################################################################
# This section has been removed to prevent deployment errors.
# The warm-up pool is no longer created.
info "Skipping honeypod warm-up pool creation."

# Kubeconfig automatisch verfügbar machen
mkdir -p $HOME/.kube
cp -f "$HIVE_STACK/cluster_kubeconfig/config_host" $HOME/.kube/config
# Alternativ (Symlink):
# ln -sf "$HIVE_STACK/cluster_kubeconfig/config_host" $HOME/.kube/config

info "Kubeconfig wurde nach ~/.kube/config kopiert. kubectl ist jetzt ohne Pfadangabe nutzbar."
