# /opt/madcat/redirector.py
import os
import redis
import json
import subprocess
import ipaddress
import time
import logging
import threading
import shutil

# Konfiguration über Umgebungsvariablen
HIVE_IP = os.getenv("HIVE_IP", "127.0.0.1")
MADCAT_IP = os.getenv("MADCAT_INTERFACE_IP", "127.0.0.1")
CHANNEL = "honeypod-map"
TTL = 1800  # TTL für Regeln

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("redirector")

# Redis-Verbindung
r = redis.Redis.from_url(f"redis://{HIVE_IP}:6379", decode_responses=True)
rules = {}  # src_ip → (dst_ip, expires)

# Bestimme geeignetes iptables-Binary (legacy bevorzugt)
IPT_BIN = shutil.which("iptables-legacy") or shutil.which("iptables") or "iptables"
log.info(f"Nutze iptables-Binary: {IPT_BIN}")


def ipt(action, src, dst, madcat_ip):
    """Wrapper für iptables-Aufrufe mit ausführlichem Logging."""
    for chain_cmd in [
        [IPT_BIN, "-t", "nat", action, "PREROUTING", "-s", src, "-j", "DNAT", "--to-destination", dst],
        [IPT_BIN, "-t", "nat", action, "POSTROUTING", "-d", dst, "-j", "SNAT", "--to-source", madcat_ip],
    ]:
        log.debug("iptables cmd: %s", " ".join(chain_cmd))
        subprocess.run(chain_cmd, check=True)


def apply_map(msg, madcat_ip):
    try:
        data = json.loads(msg)
        src = data["src"]
        dst = data["dst"]
        ipaddress.ip_address(src)
        ipaddress.ip_address(dst)
        exp = int(time.time()) + int(data.get("ttl", TTL))

        if src in rules:
            rules[src] = (dst, exp)
            log.info(f"🔁 Verlängere TTL für {src} → {dst}")
            return

        ipt("-A", src, dst, madcat_ip)
        rules[src] = (dst, exp)
        log.info(f"➡️  DNAT gesetzt: {src} → {dst} (TTL {TTL}s)")
    except Exception as e:
        log.warning(f"Fehlerhafte Nachricht: {msg} → {e}")


def gc_loop(madcat_ip):
    while True:
        now = int(time.time())
        for src in list(rules):
            dst, exp = rules[src]
            if exp < now:
                try:
                    ipt("-D", src, dst, madcat_ip)
                    del rules[src]
                    log.info(f"🗑 Entferne abgelaufene Regel: {src}")
                except Exception as e:
                    log.error(f"Fehler beim Entfernen: {e}")
        time.sleep(10)


if __name__ == "__main__":
    threading.Thread(target=gc_loop, args=(MADCAT_IP,), daemon=True).start()
    log.info(f"⏳ Listening on {CHANNEL} ...")
    pubsub = r.pubsub()
    pubsub.subscribe(CHANNEL)
    for msg in pubsub.listen():
        if msg["type"] == "message":
            apply_map(msg["data"], MADCAT_IP)
