#!/usr/bin/env python3
"""
dev_parser_unifi_protect_messages.py

One-shot utility to:
  - Ensure UniFi Protect service on UDM/UDM SE is patched with --tls-keylog
  - Delete any existing remote keylog (to avoid append/duplicates)
  - Restart service, wait until active
  - Wait for fresh /tmp/unifiprotectsslkeys.log to reappear and settle
  - Download it to a local directory
  - Verify local hash matches the post-restart remote snapshot
  - (optional) Start a live capture until TLS ServerHello or HTTP 101 Upgrade is seen

Auth:
  - SSH user is hard-coded to 'root'
  - If env UFP_ROOT_PASS is set and 'sshpass' exists, non-interactive auth is used.
  - Otherwise it falls back to the normal ssh/scp interactive password prompt.

Example:
  python3 dev_parser_unifi_protect_messages.py \
    --host 192.168.0.1 \
    --keylog-dir ./protect_artifacts \
    --keylog-timestamp \
    --capture-after --iface br0 --camera-ip 192.168.0.151 --decode-as 7442 \
    --save-pcap ./protect_artifacts/handshake_capture.pcap
"""

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime

# ---- constants ----
REMOTE_SERVICE = "/lib/systemd/system/unifi-protect.service"
REMOTE_KEYLOG  = "/tmp/unifiprotectsslkeys.log"
TLS_SENTINEL   = "--tls-keylog /tmp/unifiprotectsslkeys.log"
SSH_USER       = "root"  # hard-coded

# ---- small helpers ----
def which(prog: str):
    from shutil import which as _which
    return _which(prog)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def ssh_common_opts(port=22, key=None):
    opts = [
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=90s",
        "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
    ]
    if key:
        opts += ["-i", key]
    return opts

def build_ssh_cmd(host, *, port=22, key=None, password_env=None):
    """
    Returns argv for ssh, optionally prefixed with sshpass if:
      - password_env is set AND
      - sshpass exists on PATH
    """
    base = ["ssh"] + ssh_common_opts(port, key) + [f"{SSH_USER}@{host}"]
    if password_env and which("sshpass"):
        return ["sshpass", "-p", password_env] + base
    return base

def build_scp_cmd(host, *, port=22, key=None, password_env=None):
    base = ["scp",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=90s",
            "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
            "-P", str(port)]
    if key:
        base += ["-i", key]
    if password_env and which("sshpass"):
        return ["sshpass", "-p", password_env] + base
    return base

def run_ssh(host, remote_cmd, *, port=22, key=None, password_env=None, check=True):
    cmd = build_ssh_cmd(host, port=port, key=key, password_env=password_env) + [remote_cmd]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        if check:
            try:
                sys.stderr.write(e.output.decode("utf-8", errors="replace"))
            except Exception:
                pass
            raise
        return ""

def scp_download(host, remote_path, local_path, *, port=22, key=None, password_env=None):
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    cmd = build_scp_cmd(host, port=port, key=key, password_env=password_env) + [
        f"{SSH_USER}@{host}:{remote_path}",
        local_path,
    ]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

def has_tls_sentinel(host, service_path, *, port=22, key=None, password_env=None):
    """
    Return (present: bool, line: str) indicating whether the service file's ExecStart line
    already includes the --tls-keylog flag.
    """
    grep_cmd = f"grep -E '^ExecStart=' {service_path} 2>/dev/null || true"
    out = run_ssh(host, f"sh -lc {shlex.quote(grep_cmd)}",
                  port=port, key=key, password_env=password_env, check=False).strip()
    if not out:
        return False, ""
    for line in out.splitlines():
        if "--tls-keylog" in line:
            return True, line
    return False, out.splitlines()[0]

def patch_execstart_to_add_tls(host, *, port=22, key=None, password_env=None):
    script = r'''
set -e
FILE="''' + REMOTE_SERVICE + r'''"
TMP="/tmp/unifi-protect.service.$$"
[ -f "$FILE" ]

if grep -E '^ExecStart=' "$FILE" | grep -q -- '--tls-keylog'; then
  echo "Already contains --tls-keylog"
  exit 0
fi

awk '
BEGIN { patched=0 }
{
  if ($0 ~ /^ExecStart=/ && $0 ~ /\/usr\/bin\/node20/ && $0 !~ /--tls-keylog/) {
    gsub(/\/usr\/bin\/node20/, "/usr/bin/node20 --tls-keylog /tmp/unifiprotectsslkeys.log");
    patched=1
  }
  print
}
END { if (patched==0) exit 5 }
' "$FILE" > "$TMP"

install -m 0644 "$TMP" "$FILE"
rm -f "$TMP"
'''
    run_ssh(host, f"sh -lc {shlex.quote(script)}",
            port=port, key=key, password_env=password_env, check=True)

def daemon_reload(host, *, port=22, key=None, password_env=None):
    run_ssh(host, "sh -lc 'systemctl daemon-reload'",
            port=port, key=key, password_env=password_env, check=True)

def wait_service_active(host, *, port=22, key=None, password_env=None, timeout_s=30) -> bool:
    script = f"""
set -e
end=$(( $(date +%s) + {int(timeout_s)} ))
while [ "$(systemctl is-active unifi-protect || true)" != "active" ]; do
  [ $(date +%s) -ge $end ] && exit 7
  sleep 1
done
echo active
""".strip()
    out = run_ssh(host, f"sh -lc {shlex.quote(script)}",
                  port=port, key=key, password_env=password_env, check=False).strip()
    return out == "active"

def remote_stat_keylog(host, *, port=22, key=None, password_env=None):
    """
    Return dict {'exists': bool, 'size': int, 'sha256': str} for the remote keylog.
    Uses stat & sha256sum if available; if sha256sum is missing, sha256 is ''.
    """
    # Size
    size_cmd = f"sh -lc {shlex.quote(f'if [ -f {REMOTE_KEYLOG} ]; then stat -c %s {REMOTE_KEYLOG} 2>/dev/null || busybox stat -c %s {REMOTE_KEYLOG} 2>/dev/null; fi')}"
    size_out = run_ssh(host, size_cmd, port=port, key=key, password_env=password_env, check=False).strip()
    exists = bool(size_out)
    size = int(size_out) if size_out else 0

    if not exists:
        return {"exists": False, "size": 0, "sha256": ""}

    # Hash
    hash_cmd = f"sh -lc {shlex.quote(f'(command -v sha256sum >/dev/null 2>&1 && sha256sum {REMOTE_KEYLOG}) || (command -v busybox >/dev/null 2>&1 && busybox sha256sum {REMOTE_KEYLOG}) || echo NOHASH')}"
    hline = run_ssh(host, hash_cmd, port=port, key=key, password_env=password_env, check=False).strip()
    if not hline or hline == "NOHASH":
        return {"exists": True, "size": size, "sha256": ""}
    return {"exists": True, "size": size, "sha256": hline.split()[0]}

def remove_remote_file(host, path, *, port=22, key=None, password_env=None):
    run_ssh(host, f"sh -lc {shlex.quote(f'rm -f {path} || true')}",
            port=port, key=key, password_env=password_env, check=False)

def wait_keylog_recreated_and_settled(host, *, port=22, key=None, password_env=None,
                                      min_wait=1, settle_window=2, timeout_s=60):
    """
    Wait until keylog exists and its size is stable for 'settle_window' seconds.
    Returns latest {'exists','size','sha256'} or {'exists':False,...} on timeout.
    """
    start = time.time()
    last_size = -1
    last_change = time.time()
    time.sleep(max(0, min_wait))
    while time.time() - start < timeout_s:
        s = remote_stat_keylog(host, port=port, key=key, password_env=password_env)
        if s["exists"]:
            if s["size"] != last_size:
                last_size = s["size"]
                last_change = time.time()
            else:
                if time.time() - last_change >= settle_window and s["size"] > 0:
                    return s
        time.sleep(0.5)
    return {"exists": False, "size": 0, "sha256": ""}

def same_hash(local_path, remote_sha256):
    if not remote_sha256:
        return False
    if not local_path or not os.path.isfile(local_path):
        return False
    return sha256_file(local_path) == remote_sha256

def find_latest_local_path(dirpath: str):
    """
    Return the most recently modified local keylog file path matching:
      - unifiprotectsslkeys_*.log
      - unifiprotectsslkeys_latest.log
    or None if none exist.
    """
    if not os.path.isdir(dirpath):
        return None
    candidates = []
    for name in os.listdir(dirpath):
        if not name.startswith("unifiprotectsslkeys_") and name != "unifiprotectsslkeys_latest.log":
            continue
        full = os.path.join(dirpath, name)
        if os.path.isfile(full):
            candidates.append((os.path.getmtime(full), full))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]

def build_local_path(dirpath: str, use_timestamp: bool) -> str:
    os.makedirs(dirpath, exist_ok=True)
    if use_timestamp:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return os.path.join(dirpath, f"unifiprotectsslkeys_{ts}.log")
    else:
        return os.path.join(dirpath, "unifiprotectsslkeys_latest.log")

# ---- packet capture ----

def _decode_as_args(decode_as: str):
    args = []
    ports = [p.strip() for p in (decode_as or "7442").split(",")]
    for p in ports:
        if p.isdigit():
            args += ["-d", f"tcp.port=={p},ssl"]
    return args

def capture_until_hello(*, host, port, key, password, iface="br0",
                        camera_ip=None, duration=60, keylog_path=None,
                        save_pcap=None, decode_as="7442"):
    """
    Starts tcpdump remotely and streams packets locally to tshark until a
    TLS ServerHello or HTTP 101 Upgrade is detected.
    """
    # Build remote tcpdump
    bpf = "port 7442"
    if camera_ip:
        bpf += f" and (src host {camera_ip} or dst host {camera_ip})"
    tcpdump_cmd = f"sudo tcpdump -U -s0 -i {shlex.quote(iface)} -w - '{bpf}'"
    ssh_cmd = build_ssh_cmd(host, port=port, key=key, password_env=password) + [f"sh -lc {shlex.quote(tcpdump_cmd)}"]

    # Build tshark (decoder + filter)
    tshark_cmd = [
        "tshark",
        "-r", "-", "-l",
        "-n",
    ] + _decode_as_args(decode_as) + [
        "-T", "fields", "-e", "_ws.col.Info",
        "-Y", 'tls.handshake.type == 2 or (http.response.code == 101 && http.upgrade == "websocket")',
    ]
    if keylog_path:
        tshark_cmd += ["-o", f"tls.keylog_file:{keylog_path}"]

    # Optional pcap tee
    pcap_out = open(save_pcap, "wb") if save_pcap else None

    ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tshark_proc = subprocess.Popen(
        tshark_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1
    )

    detected = False

    # Forward tcpdump stdout → tshark stdin (and optionally save locally)
    def forwarder():
        try:
            while True:
                chunk = ssh_proc.stdout.read(65536)
                if not chunk:
                    break
                if pcap_out:
                    pcap_out.write(chunk)
                try:
                    tshark_proc.stdin.buffer.write(chunk)
                    tshark_proc.stdin.flush()
                except BrokenPipeError:
                    break
        finally:
            if pcap_out:
                pcap_out.close()
            try:
                tshark_proc.stdin.close()
            except Exception:
                pass

    import threading
    threading.Thread(target=forwarder, daemon=True).start()

    print("[capture] Waiting for ServerHello or WebSocket Upgrade…")
    start = time.time()
    try:
        while True:
            line = tshark_proc.stdout.readline()
            if not line:
                # give it a little time in case of buffering
                if (time.time() - start) > duration:
                    break
                continue
            if line.strip():
                print(f"[capture] Detected: {line.strip()}")
                detected = True
                break
            if (time.time() - start) > duration:
                break
    finally:
        try: ssh_proc.terminate()
        except Exception: pass
        try: tshark_proc.terminate()
        except Exception: pass

    if not detected:
        print("[capture] WARNING: No ServerHello/Upgrade detected within timeout.")
    else:
        print("[capture] Done (hello seen).")
    return detected

# ---- main flow ----
def main():
    ap = argparse.ArgumentParser(description="Ensure TLS keylog patch, refresh keylog, and fetch it.")
    ap.add_argument("--host", required=True, help="UDM/UDM SE IP/hostname")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--key", default=None, help="SSH private key (optional)")
    ap.add_argument("--keylog-dir", required=True, help="Local directory to store key log")
    # legacy alias (hidden)
    ap.add_argument("--timestamp", action="store_true", help=argparse.SUPPRESS)
    # preferred flag
    ap.add_argument("--keylog-timestamp", action="store_true", help="Save with UTC timestamped filename")

    # optional live capture
    ap.add_argument("--capture-after", action="store_true",
                    help="After fetching the fresh keylog, start a live capture until ServerHello/Upgrade is seen")
    ap.add_argument("--iface", default="br0", help="Remote capture interface (default: br0)")
    ap.add_argument("--camera-ip", default="", help="Optional camera IP to narrow capture")
    ap.add_argument("--decode-as", default="7442", help="Comma-separated ports to decode as TLS (default: 7442)")
    ap.add_argument("--capture-timeout", type=int, default=60, help="Max seconds to wait for hello (default: 60)")
    ap.add_argument("--save-pcap", default="", help="Optional path to save live capture stream (e.g. ./protect_artifacts/handshake_capture.pcap)")

    args = ap.parse_args()
    if args.timestamp:
        args.keylog_timestamp = True  # back-compat alias

    host     = args.host
    port     = args.port
    key_path = args.key

    # Auth env: prefer UFP_ROOT_PASS
    password_env = os.getenv("UFP_ROOT_PASS")
    if password_env:
        print("[auth] Using password from environment (UFP_ROOT_PASS).")
        if not which("sshpass"):
            print("[auth] Note: 'sshpass' not found; ssh/scp will still prompt if password is required.")

    # 1) Ensure service is patched
    present, _ = has_tls_sentinel(host, REMOTE_SERVICE, port=port, key=key_path, password_env=password_env)
    if not present:
        print("[svc] Patching ExecStart with --tls-keylog …")
        patch_execstart_to_add_tls(host, port=port, key=key_path, password_env=password_env)
        daemon_reload(host, port=port, key=key_path, password_env=password_env)
    else:
        print("[svc] TLS keylog already present in ExecStart.")

    # 2) Pre-restart snapshot (may exist if Protect is running)
    pre = remote_stat_keylog(host, port=port, key=key_path, password_env=password_env)
    print(f"[remote-pre] exists={pre['exists']} size={pre['size']} hash={pre['sha256'][:12]}…")

    # 3) Latest local
    latest_local = find_latest_local_path(args.keylog_dir)
    have_local = bool(latest_local)
    print(f"[local] have_local={'YES' if have_local else 'NO'} path={latest_local or '-'}")

    # 4) Always rotate remote file to avoid append/dupes
    if pre["exists"]:
        print("[remote] deleting existing /tmp keylog before restart to avoid append/dupes …")
        remove_remote_file(host, REMOTE_KEYLOG, port=port, key=key_path, password_env=password_env)

    # (optionally remove stale local if present so we always keep only the newest)
    if have_local:
        try:
            os.remove(latest_local)
            print(f"[local] deleted stale file: {latest_local}")
        except Exception:
            pass

    # 5) Restart + wait active
    print("[svc] restarting unifi-protect …")
    run_ssh(host, "sh -lc 'systemctl daemon-reload; systemctl restart unifi-protect'",
            port=port, key=key_path, password_env=password_env, check=True)
    print("[svc] waiting for service to become active …")
    if not wait_service_active(host, port=port, key=key_path, password_env=password_env, timeout_s=60):
        print("[svc] ERROR: service did not become active within timeout.")
        return 3

    # 6) Wait for keylog to be recreated & settled; post snapshot
    post = wait_keylog_recreated_and_settled(host, port=port, key=key_path, password_env=password_env,
                                             min_wait=1, settle_window=2, timeout_s=60)
    if not post["exists"]:
        print("[fetch] ERROR: keylog did not reappear after restart.")
        return 4
    print(f"[remote-post] size={post['size']} hash={post['sha256'][:12]}…")

    # 7) Download
    local_path = build_local_path(args.keylog_dir, getattr(args, "keylog_timestamp", False))
    scp_download(host, REMOTE_KEYLOG, local_path, port=port, key=key_path, password_env=password_env)
    print(f"[fetch] downloaded keylog to: {local_path}")

    # 8) Verify
    ok = same_hash(local_path, post["sha256"])
    print(f"[verify] local hash matches remote (post-restart)? {'YES' if ok else 'NO'}")

    # 9) Optional live capture until Hello
    if args.capture_after:
        save_pcap_path = args.save_pcap or os.path.join(args.keylog_dir, "handshake_capture.pcap")
        capture_until_hello(
            host=host,
            port=port,
            key=key_path,
            password=password_env,
            iface=args.iface,
            camera_ip=(args.camera_ip or None),
            duration=args.capture_timeout,
            keylog_path=local_path,     # not strictly needed for detection, useful if you want decryption in tshark
            save_pcap=save_pcap_path,
            decode_as=args.decode_as,
        )

    return 0 if ok else 5

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(130)
