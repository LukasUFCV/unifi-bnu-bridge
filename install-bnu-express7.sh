#!/bin/sh
set -eu

BNU_DIR="/data/bnu-proxy"
ONBOOT_DIR="/data/on_boot.d"
PY_SCRIPT="$BNU_DIR/bnu_bridge.py"
PY_BACKUP="$BNU_DIR/bnu_bridge.py.ok"
PY_HASH_FILE="$BNU_DIR/bnu_bridge.sha256"
ONBOOT_SCRIPT="$ONBOOT_DIR/22-bnu-bridge.sh"
UDBOOT_INSTALL_URL="https://raw.githubusercontent.com/unifi-utilities/unifios-utilities/HEAD/on-boot-script-2.x/remote_install.sh"

APT_UPDATED=0

log() {
  printf '%s %s\n' "$(date '+%F %T')" "$*"
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Erreur: ce script doit être lancé en root." >&2
    exit 1
  fi
}

apt_install() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Erreur: apt-get introuvable." >&2
    exit 1
  fi

  if [ "$APT_UPDATED" -eq 0 ]; then
    log "apt-get update..."
    apt-get update
    APT_UPDATED=1
  fi

  log "Installation paquet(s): $*"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

install_udm_boot_if_needed() {
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'udm-boot.service'; then
    log "udm-boot.service déjà présent."
    return 0
  fi

  log "udm-boot.service absent, installation via on-boot-script-2.x..."

  if ! command -v curl >/dev/null 2>&1; then
    apt_install curl
  fi

  TMP_SCRIPT="$(mktemp)"
  trap 'rm -f "$TMP_SCRIPT"' EXIT INT TERM

  curl -fsSL "$UDBOOT_INSTALL_URL" -o "$TMP_SCRIPT"
  bash "$TMP_SCRIPT"
  rm -f "$TMP_SCRIPT"
  trap - EXIT INT TERM

  if ! systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'udm-boot.service'; then
    echo "Erreur: udm-boot.service est toujours absent après installation." >&2
    exit 1
  fi

  log "udm-boot.service installé."
}

write_python_script() {
  mkdir -p "$BNU_DIR"

  cat > "$PY_SCRIPT" <<'PY'
#!/usr/bin/env python3
from datetime import datetime
import socket
import threading
import time
import traceback
import subprocess
import importlib
import shutil
import sys
import os

TUN_IFACE = "tun1"
LAN_IFACE = "br0"
WDS_IP = "192.168.5.222"
RELAY_IP = None
LOGFILE = "/data/bnu-proxy/bnu-bridge.log"

def ensure_scapy():
    global sniff, send, sendp, Ether, IP, UDP, BOOTP, raw, get_if_hwaddr

    try:
        from scapy.all import sniff, send, sendp, Ether, IP, UDP, BOOTP, raw, get_if_hwaddr
        return
    except ModuleNotFoundError:
        print("Scapy manquant, installation de python3-scapy...", flush=True)

    if shutil.which("apt-get") is None:
        raise RuntimeError("apt-get introuvable, impossible d'installer python3-scapy automatiquement.")

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("Le script doit être lancé en root pour installer python3-scapy automatiquement.")

    subprocess.run(["apt-get", "update"], check=True)
    subprocess.run(["apt-get", "install", "-y", "python3-scapy"], check=True)

    importlib.invalidate_caches()
    from scapy.all import sniff, send, sendp, Ether, IP, UDP, BOOTP, raw, get_if_hwaddr

def get_iface_ipv4(iface):
    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", iface],
        capture_output=True,
        text=True,
        check=True,
    )

    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            ip_cidr = parts[parts.index("inet") + 1]
            return ip_cidr.split("/")[0]

    raise RuntimeError(f"Aucune IPv4 trouvée sur l'interface {iface}")

pending = {}
lock = threading.Lock()

def log(msg):
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} {msg}"
    print(line, flush=True)
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def cleanup_pending():
    now = time.time()
    with lock:
        old = [x for x, ts in pending.items() if now - ts > 30]
        for x in old:
            pending.pop(x, None)

def mark_pending(xid):
    with lock:
        pending[xid] = time.time()

def is_pending(xid):
    with lock:
        return xid in pending

def unmark_pending(xid):
    with lock:
        pending.pop(xid, None)

def mac_from_chaddr(chaddr):
    b = bytes(chaddr[:6])
    return ":".join(f"{x:02x}" for x in b)

def looks_like_bitlocker_request(pkt):
    if IP not in pkt or UDP not in pkt or BOOTP not in pkt:
        return False
    if pkt[UDP].dport != 67:
        return False
    if pkt[IP].src == WDS_IP:
        return False

    payload = raw(pkt[BOOTP])

    if b"BITLOCKER" not in payload:
        return False
    if b"\x63\x82\x53\x63" not in payload:
        return False

    return True

def forward_bitlocker_request(pkt):
    try:
        bootp = pkt[BOOTP]
        payload = bytearray(raw(bootp))

        if len(payload) < 28:
            log("SKIP short BOOTP payload")
            return

        xid = bootp.xid

        # IMPORTANT: on marque AVANT l'envoi pour éviter la course
        mark_pending(xid)

        # BOOTP fixed header
        # byte 3 = hops
        # bytes 20:24 = siaddr
        # bytes 24:28 = giaddr
        payload[3] = min(payload[3] + 1, 255)
        payload[20:24] = socket.inet_aton(WDS_IP)
        payload[24:28] = socket.inet_aton(RELAY_IP)

        out = IP(src=RELAY_IP, dst=WDS_IP, tos=0xc0) / UDP(sport=67, dport=67) / bytes(payload)
        send(out, iface=TUN_IFACE, verbose=False)

        log(
            f"FWD request xid=0x{xid:08x} "
            f"client_mac={mac_from_chaddr(bootp.chaddr)} "
            f"ciaddr={bootp.ciaddr} yiaddr={bootp.yiaddr} siaddr={bootp.siaddr} "
            f"to WDS {WDS_IP} via {TUN_IFACE}"
        )
    except Exception as e:
        log(f"ERROR forward: {e}")
        log(traceback.format_exc())

def handle_lan(pkt):
    cleanup_pending()
    if looks_like_bitlocker_request(pkt):
        forward_bitlocker_request(pkt)

def handle_tun(pkt):
    try:
        cleanup_pending()

        if IP not in pkt or UDP not in pkt or BOOTP not in pkt:
            return

        ip = pkt[IP]
        udp = pkt[UDP]
        bootp = pkt[BOOTP]

        if ip.src != WDS_IP:
            return
        if udp.sport != 67 or udp.dport != 67:
            return
        if getattr(bootp, "op", None) != 2:
            return

        xid = bootp.xid

        if not is_pending(xid):
            log(f"DROP unsolicited reply xid=0x{xid:08x} from {WDS_IP}")
            return

        payload = raw(bootp)

        out = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(LAN_IFACE)) /
            IP(src=RELAY_IP, dst="255.255.255.255", tos=0xc0) /
            UDP(sport=67, dport=68) /
            payload
        )

        sendp(out, iface=LAN_IFACE, verbose=False)
        log(
            f"REBROADCAST reply xid=0x{xid:08x} "
            f"client_mac={mac_from_chaddr(bootp.chaddr)} "
            f"yiaddr={bootp.yiaddr} siaddr={bootp.siaddr} "
            f"from WDS {WDS_IP} to broadcast on {LAN_IFACE}"
        )
        unmark_pending(xid)

    except Exception as e:
        log(f"ERROR reply: {e}")
        log(traceback.format_exc())

def sniff_lan():
    sniff(
        iface=LAN_IFACE,
        filter="udp and dst port 67",
        prn=handle_lan,
        store=False,
    )

def sniff_tun():
    sniff(
        iface=TUN_IFACE,
        filter=f"udp and src host {WDS_IP} and src port 67 and dst port 67",
        prn=handle_tun,
        store=False,
    )

def main():
    global RELAY_IP

    ensure_scapy()
    RELAY_IP = get_iface_ipv4(LAN_IFACE)
    log(f"Starting BNU bridge LAN={LAN_IFACE} TUN={TUN_IFACE} WDS={WDS_IP} RELAY_IP={RELAY_IP}")

    t1 = threading.Thread(target=sniff_lan, daemon=True)
    t2 = threading.Thread(target=sniff_tun, daemon=True)

    t1.start()
    t2.start()

    while True:
        time.sleep(60)
        cleanup_pending()

if __name__ == "__main__":
    main()
PY

  chmod +x "$PY_SCRIPT"
  cp "$PY_SCRIPT" "$PY_BACKUP"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$PY_SCRIPT" "$PY_BACKUP" > "$PY_HASH_FILE"
  fi

  touch "$BNU_DIR/bnu-bridge.log" "$BNU_DIR/bnu-bridge.stdout"

  log "Fichier Python créé: $PY_SCRIPT"
}

write_onboot_script() {
  mkdir -p "$ONBOOT_DIR"

  cat > "$ONBOOT_SCRIPT" <<'SH'
#!/bin/sh

PIDFILE=/run/bnu-reply-relay.pid
SCRIPT=/data/bnu-proxy/bnu_bridge.py
STDOUT_LOG=/data/bnu-proxy/bnu-bridge.stdout

mkdir -p /data/bnu-proxy

# Stop ancienne instance
if [ -f "$PIDFILE" ]; then
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
fi
pkill -f "$SCRIPT" 2>/dev/null || true
rm -f "$PIDFILE"

# Attente interfaces/routage
for i in $(seq 1 30); do
  ip link show br0 >/dev/null 2>&1 && ip link show tun1 >/dev/null 2>&1 && break
  sleep 2
done

ip route replace 192.168.5.222/32 dev tun1

# Redémarrage propre
nohup python3 "$SCRIPT" >"$STDOUT_LOG" 2>&1 &
echo $! > "$PIDFILE"
SH

  chmod +x "$ONBOOT_SCRIPT"
  log "Script on-boot créé: $ONBOOT_SCRIPT"
}

ensure_python_runtime() {
  if ! command -v python3 >/dev/null 2>&1; then
    apt_install python3
  fi

  if ! python3 -c "import scapy.all" >/dev/null 2>&1; then
    apt_install python3-scapy
  fi
}

run_bridge_now() {
  log "Lancement immédiat du bridge..."
  "$ONBOOT_SCRIPT"
  sleep 3
}

start_udm_boot() {
  systemctl daemon-reload || true
  systemctl enable udm-boot 2>/dev/null || true
  systemctl reset-failed udm-boot 2>/dev/null || true
  systemctl restart udm-boot 2>/dev/null || systemctl start udm-boot 2>/dev/null || true
  sleep 3
}

show_status() {
  log "===== VERIFICATIONS ====="
  systemctl status udm-boot --no-pager || true
  echo "----- PIDFILE -----"
  cat /run/bnu-reply-relay.pid 2>/dev/null || true
  echo "----- PROCESS -----"
  pgrep -af bnu_bridge.py || true
  echo "----- LOG -----"
  tail -n 20 "$BNU_DIR/bnu-bridge.log" 2>/dev/null || true
  echo "----- STDOUT -----"
  tail -n 20 "$BNU_DIR/bnu-bridge.stdout" 2>/dev/null || true
  echo "----- ROUTE WDS -----"
  ip route get 192.168.5.222 || true
  echo "----- HASH -----"
  if [ -f "$PY_HASH_FILE" ]; then
    cat "$PY_HASH_FILE"
  fi
}

main() {
  need_root
  mkdir -p "$BNU_DIR" "$ONBOOT_DIR"

  ensure_python_runtime
  install_udm_boot_if_needed
  write_python_script
  write_onboot_script
  run_bridge_now
  start_udm_boot
  show_status

  log "Installation BNU Express 7 terminée."
}

main "$@"
