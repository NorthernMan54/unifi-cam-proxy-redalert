#!/usr/bin/env python3
"""
dev_parser_unifi_protect_messages.py

Remotely manage UniFi Protect service TLS key logging on a UDM/UDM SE.
Now includes tshark-based capture and parsing (no Wireshark GUI required).
"""

import argparse
import os
import shlex
import subprocess
import sys
import shutil
from time import sleep
from datetime import datetime
from typing import List

REMOTE_SERVICE = "/lib/systemd/system/unifi-protect.service"
TLS_SENTINEL = "--tls-keylog /tmp/unifiprotectsslkeys.log"
REMOTE_KEYLOG = "/tmp/unifiprotectsslkeys.log"

# ---------------- SSH helpers ----------------

def ssh_common_opts(port=22, key=None):
    # Reuse a single control connection for N seconds
    return [
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=90s",
        "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
    ] + (["-i", key] if key else [])

def ssh_base(user, host, port=22, key=None):
    return ["ssh"] + ssh_common_opts(port, key) + [f"{user}@{host}"]

def run_ssh(user, host, remote_cmd, port=22, key=None, check=True):
    """Run a command over SSH, return stdout (str)."""
    cmd = ssh_base(user, host, port, key) + [remote_cmd]
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

def scp_download(user, host, remote_path, local_path, port=22, key=None):
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    cmd = ["scp"] + ["-o", "ControlMaster=auto", "-o", "ControlPersist=90s",
                     "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
                     "-P", str(port)]
    if key:
        cmd += ["-i", key]
    cmd += [f"{user}@{host}:{remote_path}", local_path]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

# ---------------- Remote operations ----------------

def remote_file_exists(user, host, path, port=22, key=None):
    out = run_ssh(
        user, host,
        f"sh -lc {shlex.quote(f'[ -f {path} ] && echo YES || echo NO')}",
        port, key, check=True
    ).strip()
    return out == "YES"

def get_execstart_line(user, host, path, port=22, key=None):
    """Return the ExecStart= line (full) or empty string if not found."""
    grep_cmd = f"grep -E '^ExecStart=' {path} 2>/dev/null || true"
    try:
        out = run_ssh(
            user, host,
            f"sh -lc {shlex.quote(grep_cmd)}",
            port, key, check=False
        ).strip()
        if out:
            return out.splitlines()[0]
    except subprocess.CalledProcessError:
        pass
    awk_cmd = f"awk -F= '/^ExecStart=/{{print $0; exit}}' {path} 2>/dev/null || true"
    try:
        out = run_ssh(
            user, host,
            f"sh -lc {shlex.quote(awk_cmd)}",
            port, key, check=False
        ).strip()
        return out
    except subprocess.CalledProcessError:
        return ""

def has_tls_sentinel(user, host, path, port=22, key=None):
    ex = get_execstart_line(user, host, path, port, key)
    return (TLS_SENTINEL in ex), ex

def backup_service_if_needed(user, host, port=22, key=None, backup_path=None):
    """Create a one-time remote backup if it doesn't already exist."""
    if not backup_path:
        backup_path = REMOTE_SERVICE + ".bak"
    run_ssh(
        user, host,
        f"sh -lc {shlex.quote(f'[ -f {backup_path} ] || cp -f {REMOTE_SERVICE} {backup_path}')}",
        port, key, check=True
    )
    return backup_path

def patch_execstart_to_add_tls(user, host, port=22, key=None):
    """
    Safely patch ExecStart to insert TLS flag:
      --tls-keylog /tmp/unifiprotectsslkeys.log
    """
    remote_script = r'''
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
END {
  if (patched==0) exit 5
}
' "$FILE" > "$TMP"

install -m 0644 "$TMP" "$FILE"
rm -f "$TMP"
'''
    try:
        out = run_ssh(
            user, host,
            f"sh -lc {shlex.quote(remote_script)}",
            port, key, check=True
        )
        return True, out
    except subprocess.CalledProcessError:
        return False, "Patching failed (missing expected ExecStart or other error)."

def daemon_reload_and_restart(user, host, port=22, key=None):
    run_ssh(user, host, f"sh -lc {shlex.quote('systemctl daemon-reload')}", port, key, check=True)
    run_ssh(user, host, f"sh -lc {shlex.quote('systemctl restart unifi-protect')}", port, key, check=True)

def wait_active(user, host, port=22, key=None, timeout_s=30):
    script = f'''
set -e
end=$(( $(date +%s) + {int(timeout_s)} ))
while [ "$(systemctl is-active unifi-protect || true)" != "active" ]; do
  [ $(date +%s) -ge $end ] && exit 7
  sleep 1
done
systemctl is-active unifi-protect
'''
    out = run_ssh(user, host, f"sh -lc {shlex.quote(script)}", port, key, check=True).strip()
    return out == "active"

def fetch_keylog(user, host, local_dir, port=22, key=None, filename=None, timestamp=True):
    """Fetch /tmp/unifiprotectsslkeys.log to local_dir."""
    if not filename:
        if timestamp:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"unifiprotectsslkeys_{ts}.log"
        else:
            filename = "unifiprotectsslkeys.log"
    local_path = os.path.join(local_dir, filename)
    exists = run_ssh(
        user, host,
        f"sh -lc {shlex.quote(f'[ -f {REMOTE_KEYLOG} ] && echo YES || echo NO')}",
        port, key, check=True
    ).strip() == "YES"
    if not exists:
        raise FileNotFoundError(f"{REMOTE_KEYLOG} not found on remote.")
    scp_download(user, host, REMOTE_KEYLOG, local_path, port, key)
    return local_path

# ---------------- tshark helpers ----------------

def ensure_tshark():
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        print("Error: 'tshark' not found on PATH. Install with: sudo apt install -y tshark")
        sys.exit(2)
    return tshark_bin

def build_decode_as_args(ports_csv: str):
    """Return ['-d','tcp.port==7442,ssl', ...] for a comma-separated port list."""
    if not ports_csv:
        return []
    args = []
    for p in [x.strip() for x in ports_csv.split(",") if x.strip().isdigit()]:
        args += ["-d", f"tcp.port=={p},ssl"]
    return args

def build_bpf(camera_ip: str, decode_as_ports: str, default_port: int = 7442) -> str:
    """
    Build a compact BPF like:
      'port 7442 and (src host 1.2.3.4 or dst host 1.2.3.4)'
    If decode_as_ports provided, use those ports; else default to 7442.
    """
    ports = [p for p in [s.strip() for s in (decode_as_ports or str(default_port)).split(",")] if p.isdigit()]
    if len(ports) == 1:
        port_expr = f"port {ports[0]}"
    else:
        port_expr = "(" + " or ".join([f"port {p}" for p in ports]) + ")"
    ip_expr = f"(src host {camera_ip} or dst host {camera_ip})" if camera_ip else ""
    if ip_expr:
        return f"{port_expr} and {ip_expr}"
    return port_expr

def extract_websocket_payloads_from_pcap(pcap_path: str, keylog_path: str, decode_as_ports: str = "") -> List[bytes]:
    tshark = ensure_tshark()
    cmd = [
        tshark,
        "-r", pcap_path,
        "-o", f"tls.keylog_file:{keylog_path}",
        "-n",
    ] + build_decode_as_args(decode_as_ports) + [
        "-Y", "websocket",
        "-T", "fields", "-e", "websocket.payload",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.returncode}\n{proc.stderr}")
    payloads = []
    for line in proc.stdout.splitlines():
        hexline = line.strip().replace(":", "").replace(" ", "")
        if not hexline:
            continue
        try:
            payloads.append(bytes.fromhex(hexline))
        except Exception:
            pass
    return payloads

def quote_bpf_for_sh(bpf: str) -> str:
    """
    Wrap BPF for a remote 'sh -lc' safely.
    Use single quotes unless the bpf itself contains single quotes (unlikely).
    """
    if "'" in bpf:
        # Fallback: no quotes, but escape parentheses explicitly
        return bpf.replace("(", r"\(").replace(")", r"\)")
    return f"'{bpf}'"

def spawn_remote_restart_after_delay(user, host, delay_s: int, port=22, key=None):
    """
    Trigger 'systemctl restart unifi-protect' after delay on the UDM, in the background.
    Uses nohup + sleep; no parentheses or bash-isms.
    """
    delay_s = max(0, int(delay_s))
    cmd = f"nohup sh -c 'sleep {delay_s}; systemctl restart unifi-protect' >/dev/null 2>&1 &"
    # do not raise on failure so the capture can continue regardless
    try:
        run_ssh(user, host, f"sh -lc {shlex.quote(cmd)}", port, key, check=False)
    except Exception:
        pass

# ---------------- Command handlers ----------------

def cmd_check(args):
    if not remote_file_exists(args.user, args.host, REMOTE_SERVICE, args.port, args.key):
        print(f"Remote file missing: {REMOTE_SERVICE}")
        sys.exit(3)
    present, line = has_tls_sentinel(args.user, args.host, REMOTE_SERVICE, args.port, args.key)
    print("ExecStart:", line or "(not found)")
    print("TLS keylog present?:", "YES" if present else "NO")
    sys.exit(0 if present else 1)

def cmd_enforce(args):
    if not remote_file_exists(args.user, args.host, REMOTE_SERVICE, args.port, args.key):
        print(f"Remote file missing: {REMOTE_SERVICE}")
        sys.exit(3)
    present, line = has_tls_sentinel(args.user, args.host, REMOTE_SERVICE, args.port, args.key)
    print("Before:", line or "(not found)")
    if present:
        print("TLS keylog already present; no edit needed.")
    else:
        backup = backup_service_if_needed(args.user, args.host, args.port, args.key, args.remote_backup_path)
        print(f"Ensured remote backup at: {backup}")
        ok, msg = patch_execstart_to_add_tls(args.user, args.host, args.port, args.key)
        if not ok:
            print(msg)
            sys.exit(1)
        print("Patched ExecStart to include TLS key logging.")

    print("Reloading systemd and restarting unifi-protect...")
    try:
        daemon_reload_and_restart(args.user, args.host, args.port, args.key)
    except subprocess.CalledProcessError:
        print("Failed to restart unifi-protect.")
        sys.exit(2)

    print("Waiting for service to become active...")
    if not wait_active(args.user, args.host, args.port, args.key, args.start_timeout):
        print("Service did not become active within timeout.")
        sys.exit(1)
    print("Service is active.")

    present, line = has_tls_sentinel(args.user, args.host, REMOTE_SERVICE, args.port, args.key)
    print("After :", line or "(not found)")
    if not present:
        print("ERROR: TLS keylog flag not present after restart.")
        sys.exit(1)
    print("Verified TLS keylog flag present.")

    if args.keylog_dir:
        try:
            path = fetch_keylog(
                args.user, args.host,
                args.keylog_dir,
                args.port, args.key,
                filename=args.keylog_filename,
                timestamp=args.keylog_timestamp,
            )
            print(f"Fetched key log to: {path}")
        except FileNotFoundError as e:
            print(f"Warning: {e}")

    if args.save_local_copy:
        try:
            scp_download(args.user, args.host, REMOTE_SERVICE, args.save_local_copy, args.port, args.key)
            print(f"Saved local copy of service file to: {args.save_local_copy}")
        except subprocess.CalledProcessError:
            print("Warning: failed to download local copy of service file.")
    sys.exit(0)

def cmd_fetch_keys(args):
    try:
        path = fetch_keylog(
            args.user, args.host,
            args.keylog_dir,
            args.port, args.key,
            filename=args.keylog_filename,
            timestamp=args.keylog_timestamp,
        )
        print(f"Fetched key log to: {path}")
        sys.exit(0)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(3)
    except subprocess.CalledProcessError:
        print("SCP failed.")
        sys.exit(2)

def cmd_live_capture(args):
    wireshark_bin = shutil.which("wireshark") or shutil.which("Wireshark")
    tshark_bin = shutil.which("tshark")
    if not wireshark_bin and not tshark_bin:
        print("Error: neither 'wireshark' nor 'tshark' found on local PATH. Install Wireshark or tshark.")
        sys.exit(2)

    remote_filter = f"src host {args.camera_ip} or dst host {args.camera_ip}" if args.camera_ip else ""
    tcpdump_cmd = f"sudo tcpdump -U -s0 -i {shlex.quote(args.iface)} -w - {remote_filter}".strip()
    if args.duration and int(args.duration) > 0:
        tcpdump_cmd = f"timeout {int(args.duration)} {tcpdump_cmd}"
    ssh_cmd = ssh_base(args.user, args.host, args.port, args.key) + [f"sh -lc {shlex.quote(tcpdump_cmd)}"]
    print("Running remote capture:", tcpdump_cmd)

    try:
        ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if wireshark_bin:
            wiz_cmd = [wireshark_bin, "-k", "-i", "-"]
            print("Launching local Wireshark...")
            wiz_proc = subprocess.Popen(wiz_cmd, stdin=ssh_proc.stdout)
            ssh_proc.stdout.close()
            import threading
            def fwd(p):
                for line in p.stderr:
                    sys.stderr.buffer.write(line)
                p.stderr.close()
            threading.Thread(target=fwd, args=(ssh_proc,), daemon=True).start()
            wiz_proc.wait()
        else:
            print("wireshark not found; using tshark to display packets in console...")
            tshark_proc = subprocess.Popen([tshark_bin, "-i", "-", "-l"], stdin=ssh_proc.stdout)
            ssh_proc.stdout.close()
            tshark_proc.wait()
    finally:
        try: ssh_proc.terminate()
        except Exception: pass
        sleep(0.3)

# ---------- capture to remote file, fetch, optionally delete remote ----------

def cmd_capture_to_file(args):
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    remote_pcap = args.remote_path or f"/tmp/cap_{ts}.pcapng"
    os.makedirs(args.outdir, exist_ok=True)
    remote_filter = f"src host {args.camera_ip} or dst host {args.camera_ip}" if args.camera_ip else ""
    tcpdump_cmd = f"sudo tcpdump -U -s0 -i {shlex.quote(args.iface)} -w {shlex.quote(remote_pcap)} {remote_filter}".strip()
    if args.duration and int(args.duration) > 0:
        tcpdump_cmd = f"timeout {int(args.duration)} {tcpdump_cmd}"
    print("Remote tcpdump:", tcpdump_cmd)

    try:
        out = run_ssh(args.user, args.host, f"sh -lc {shlex.quote(tcpdump_cmd)}", args.port, args.key, check=True)
        if out:
            sys.stdout.write(out)
    except subprocess.CalledProcessError as e:
        print("ERROR: tcpdump failed on remote host.")
        try:
            sys.stderr.write(e.output.decode("utf-8", errors="replace"))
        except Exception:
            pass
        sys.exit(2)

    # Verify remote file exists and is non-empty
    try:
        exists = run_ssh(
            args.user, args.host,
            f"sh -lc {shlex.quote(f'[ -s {remote_pcap} ] && echo OK || echo MISSING')}",
            args.port, args.key, check=True
        ).strip()
    except subprocess.CalledProcessError:
        exists = "MISSING"

    if exists != "OK":
        print(f"ERROR: remote pcap not found or empty: {remote_pcap}")
        print("Hint: check interface/filter; try running without --camera-ip or with a longer --duration.")
        sys.exit(3)

    # Download
    local_pcap = os.path.join(args.outdir, os.path.basename(remote_pcap))
    print(f"Downloading {remote_pcap} -> {local_pcap}")
    try:
        scp_download(args.user, args.host, remote_pcap, local_pcap, args.port, args.key)
        print(f"Downloaded capture to: {local_pcap}")
    except subprocess.CalledProcessError:
        print("ERROR: scp download failed.")
        sys.exit(2)

    if not args.keep_remote:
        run_ssh(args.user, args.host, f"sh -lc {shlex.quote(f'rm -f {remote_pcap} || true')}", args.port, args.key, check=False)

    print("Done.")
    sys.exit(0)

# ---------- parse/decrypt a local pcap using keylog; write payloads ----------

def cmd_parse_pcap(args):
    ensure_tshark()
    if not os.path.isfile(args.pcap):
        print(f"pcap not found: {args.pcap}")
        sys.exit(3)
    if not os.path.isfile(args.keylog):
        print(f"keylog not found: {args.keylog}")
        sys.exit(3)
    os.makedirs(args.outdir, exist_ok=True)
    payloads = extract_websocket_payloads_from_pcap(args.pcap, args.keylog, decode_as_ports=args.decode_as)
    print(f"Found {len(payloads)} WebSocket frame payloads.")
    frames_dir = os.path.join(args.outdir, "frames")
    os.makedirs(frames_dir, exist_ok=True)
    combined_path = os.path.join(args.outdir, "ws_combined.bin")
    with open(combined_path, "wb") as combined:
        for i, p in enumerate(payloads):
            frame_path = os.path.join(frames_dir, f"frame_{i:06d}.bin")
            with open(frame_path, "wb") as f:
                f.write(p)
            combined.write(p)
    print(f"Wrote frames to {frames_dir}")
    print(f"Wrote combined payloads to {combined_path}")
    sys.exit(0)

# ---------- one-shot capture → fetch → parse ----------

def cmd_capture_and_parse(args):
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    remote_pcap = args.remote_path or f"/tmp/cap_{ts}.pcapng"
    os.makedirs(args.outdir, exist_ok=True)
    remote_filter = f"src host {args.camera_ip} or dst host {args.camera_ip}" if args.camera_ip else ""
    tcpdump_cmd = f"sudo tcpdump -U -s0 -i {shlex.quote(args.iface)} -w {shlex.quote(remote_pcap)} {remote_filter}".strip()
    if args.duration and int(args.duration) > 0:
        tcpdump_cmd = f"timeout {int(args.duration)} {tcpdump_cmd}"
    print("Remote tcpdump:", tcpdump_cmd)
    run_ssh(args.user, args.host, f"sh -lc {shlex.quote(tcpdump_cmd)}", args.port, args.key, check=True)

    local_pcap = os.path.join(args.outdir, os.path.basename(remote_pcap))
    scp_download(args.user, args.host, remote_pcap, local_pcap, args.port, args.key)
    print(f"Downloaded capture to: {local_pcap}")
    if not args.keep_remote:
        run_ssh(args.user, args.host, f"sh -lc {shlex.quote(f'rm -f {remote_pcap} || true')}", args.port, args.key, check=False)

    if not os.path.isfile(args.keylog):
        print(f"keylog not found: {args.keylog}")
        print("Tip: run 'fetch-keys' first to get /tmp/unifiprotectsslkeys.log")
        sys.exit(3)

    payloads = extract_websocket_payloads_from_pcap(local_pcap, args.keylog, decode_as_ports=args.decode_as)
    print(f"Found {len(payloads)} WebSocket frame payloads.")
    frames_dir = os.path.join(args.outdir, "frames")
    os.makedirs(frames_dir, exist_ok=True)
    combined_path = os.path.join(args.outdir, "ws_combined.bin")
    with open(combined_path, "wb") as combined:
        for i, p in enumerate(payloads):
            frame_path = os.path.join(frames_dir, f"frame_{i:06d}.bin")
            with open(frame_path, "wb") as f:
                f.write(p)
            combined.write(p)
    print(f"Wrote frames to {frames_dir}")
    print(f"Wrote combined payloads to {combined_path}")
    sys.exit(0)

# ---------- live stream tcpdump → local tshark (decrypt) → write frames ----------

def cmd_stream_parse(args):
    """
    Stream remote tcpdump over SSH to local tshark, decrypt with keylog, and parse websocket payloads live.
    Optionally tee raw pcap stream to a local file while parsing.
    """
    tshark = ensure_tshark()

    if not os.path.isfile(args.keylog):
        print(f"keylog not found: {args.keylog}")
        print("Tip: run 'fetch-keys' first to pull /tmp/unifiprotectsslkeys.log from the UDM.")
        sys.exit(3)

    # Build tight BPF: port(s) (default 7442) and optional camera IP
    bpf = build_bpf(args.camera_ip, args.decode_as or "7442")
    bpf_quoted = quote_bpf_for_sh(bpf)

    tcpdump_cmd = f"sudo tcpdump -U -s0 -i {shlex.quote(args.iface)} -w - {bpf_quoted}".strip()
    if args.duration and int(args.duration) > 0:
        tcpdump_cmd = f"timeout {int(args.duration)} {tcpdump_cmd}"

    ssh_cmd = ssh_base(args.user, args.host, args.port, args.key) + [f"sh -lc {shlex.quote(tcpdump_cmd)}"]
    print("Remote tcpdump:", tcpdump_cmd)
    print("Starting SSH…")

    os.makedirs(args.outdir, exist_ok=True)
    frames_dir = os.path.join(args.outdir, "frames")
    os.makedirs(frames_dir, exist_ok=True)
    combined_path = os.path.join(args.outdir, "ws_combined.bin")
    combined_f = open(combined_path, "ab")

    ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    tshark_cmd = [
        tshark,
        "-r", "-",
        "-l",
        "-o", f"tls.keylog_file:{args.keylog}",
        "-n",
    ] + build_decode_as_args(args.decode_as or "7442") + [
        "-Y", "websocket",
        "-T", "fields", "-e", "websocket.payload",
    ]
    tshark_proc = subprocess.Popen(
        tshark_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    pcap_out = None
    if args.save_pcap_stream:
        # overwrite each run to avoid corrupt concatenations
        pcap_out = open(args.save_pcap_stream, "wb")

    import threading
    def forward_stderr(proc):
        for chunk in iter(proc.stderr.readline, b""):
            try:
                sys.stderr.buffer.write(chunk)
            except Exception:
                pass
        try:
            proc.stderr.close()
        except Exception:
            pass

    threading.Thread(target=forward_stderr, args=(ssh_proc,), daemon=True).start()
    threading.Thread(target=forward_stderr, args=(tshark_proc,), daemon=True).start()

    stop_flag = {"stop": False}
    def pump_pcap():
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
            try:
                if tshark_proc.stdin:
                    tshark_proc.stdin.close()
            except Exception:
                pass
            stop_flag["stop"] = True

    pump_thread = threading.Thread(target=pump_pcap, daemon=True)
    pump_thread.start()

    print(f"Streaming… writing frames under {frames_dir} and combined to {combined_path}")
    frame_idx = 0
    try:
        for line in iter(tshark_proc.stdout.readline, ""):
            if not line:
                if stop_flag["stop"]:
                    break
                continue
            hexline = line.strip().replace(":", "").replace(" ", "")
            if not hexline:
                continue
            try:
                payload = bytes.fromhex(hexline)
            except Exception:
                continue
            frame_path = os.path.join(frames_dir, f"frame_{frame_idx:06d}.bin")
            with open(frame_path, "wb") as f:
                f.write(payload)
            combined_f.write(payload)
            frame_idx += 1
            if frame_idx % 50 == 0:
                print(f"... {frame_idx} frames")
        pump_thread.join(timeout=2)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Stopping…")
    finally:
        try:
            if pcap_out:
                pcap_out.close()
            combined_f.close()
        except Exception:
            pass
        for p in (tshark_proc, ssh_proc):
            try: p.terminate()
            except Exception: pass
        sleep(0.3)

    print(f"Done. Total frames: {frame_idx}")
    print(f"Frames dir: {frames_dir}")
    print(f"Combined file: {combined_path}")
    sys.exit(0)

# ---------- NEW: capture-handshake (force a fresh TLS/WSS handshake) ----------

# ---- add this command body somewhere with your other command handlers ----

def cmd_capture_handshake(args):
    """
    Start a tight tcpdump on the UDM, then (optionally) restart unifi-protect after a small delay
    so the TLS handshake + WSS upgrade on port 7442 are guaranteed to be in the capture.
    The raw stream is saved to --save-pcap-stream; afterwards we decrypt/parse into websocket frames.
    """
    tshark = ensure_tshark()

    if not os.path.isfile(args.keylog):
        print(f"keylog not found: {args.keylog}")
        print("Tip: run 'fetch-keys' first to pull /tmp/unifiprotectsslkeys.log from the UDM.")
        sys.exit(3)

    # Build tight BPF (default port 7442) and quote it for the remote shell.
    bpf = build_bpf(args.camera_ip, args.decode_as or "7442")
    bpf_quoted = quote_bpf_for_sh(bpf)

    # tcpdump that reads only the handshake port traffic
    tcpdump_cmd = f"sudo tcpdump -U -s0 -i {shlex.quote(args.iface)} -w - {bpf_quoted}".strip()
    if args.duration and int(args.duration) > 0:
        tcpdump_cmd = f"timeout {int(args.duration)} {tcpdump_cmd}"

    print("Remote tcpdump:", tcpdump_cmd)
    print("Starting SSH…")

    # Prepare output dirs/files
    os.makedirs(args.outdir, exist_ok=True)
    frames_dir = os.path.join(args.outdir, "frames")
    os.makedirs(frames_dir, exist_ok=True)
    combined_path = os.path.join(args.outdir, "ws_combined.bin")

    # Make sure we have a pcap destination (overwrite each run)
    if not args.save_pcap_stream:
        print("ERROR: --save-pcap-stream is required for capture-handshake (we need a pcap to parse afterwards).")
        sys.exit(2)
    pcap_path = args.save_pcap_stream
    pcap_f = open(pcap_path, "wb")

    # Spawn tcpdump over SSH
    ssh_cmd = ssh_base(args.user, args.host, args.port, args.key) + [f"sh -lc {shlex.quote(tcpdump_cmd)}"]
    ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    # Optionally trigger the restart in background (after a small pre-delay)
    if args.pre_restart_delay and int(args.pre_restart_delay) > 0:
        print(f"[capture-handshake] Waiting {int(args.pre_restart_delay)}s before restart…")
        spawn_remote_restart_after_delay(args.user, args.host, int(args.pre_restart_delay), args.port, args.key)

    # Pump bytes to pcap until tcpdump exits
    import threading
    def fwd_stderr(p):
        for line in iter(p.stderr.readline, b""):
            try:
                sys.stderr.buffer.write(line)
            except Exception:
                pass
        try:
            p.stderr.close()
        except Exception:
            pass

    threading.Thread(target=fwd_stderr, args=(ssh_proc,), daemon=True).start()

    bytes_written = 0
    try:
        while True:
            chunk = ssh_proc.stdout.read(65536)
            if not chunk:
                break
            pcap_f.write(chunk)
            bytes_written += len(chunk)
    except KeyboardInterrupt:
        pass
    finally:
        pcap_f.close()
        try:
            ssh_proc.terminate()
        except Exception:
            pass
        sleep(0.2)

    print(f"Capture complete. Wrote {bytes_written} bytes to {pcap_path}")

    # Now parse/decrypt from the saved pcap
    try:
        payloads = extract_websocket_payloads_from_pcap(pcap_path, args.keylog, decode_as_ports=args.decode_as)
    except RuntimeError as e:
        # give a more helpful hint if decryption failed
        msg = str(e)
        print("tshark parse failed. If the handshake still wasn’t in the capture, try a longer --duration, "
              "or increase --pre-restart-delay slightly (1–5s).")
        print(msg)
        sys.exit(2)

    print(f"Found {len(payloads)} WebSocket frame payloads.")
    with open(combined_path, "wb") as combined:
        for i, p in enumerate(payloads):
            frame_path = os.path.join(frames_dir, f"frame_{i:06d}.bin")
            with open(frame_path, "wb") as f:
                f.write(p)
            combined.write(p)

    print(f"Frames dir: {frames_dir}")
    print(f"Combined file: {combined_path}")
    sys.exit(0)

# ---------------- Main ----------------

def main():
    ap = argparse.ArgumentParser(description="UDM Protect TLS keylog manager, capture & parser (remote SSH + tshark)")
    ap.add_argument("--host", help="UDM IP/hostname (required for remote commands)")
    ap.add_argument("--user", help="SSH user (root recommended)")
    ap.add_argument("--port", type=int, default=22, help="SSH port")
    ap.add_argument("--key", default=None, help="SSH private key path")

    sub = ap.add_subparsers(dest="cmd", required=True)

    # check
    sp_check = sub.add_parser("check", help="Check if --tls-keylog is present")
    sp_check.set_defaults(func=cmd_check)

    # enforce
    sp_enf = sub.add_parser("enforce", help="Ensure --tls-keylog is present; restart; verify; optionally fetch keys")
    sp_enf.add_argument("--remote-backup-path", default=REMOTE_SERVICE + ".bak",
                        help="Remote backup path for the service file (created if missing)")
    sp_enf.add_argument("--start-timeout", type=int, default=30,
                        help="Seconds to wait for service to become active")
    sp_enf.add_argument("--keylog-dir", default="",
                        help="Local directory to save unifiprotectsslkeys.log (optional)")
    sp_enf.add_argument("--keylog-filename", default="",
                        help="Fixed local filename (omit to make timestamped)")
    sp_enf.add_argument("--keylog-timestamp", action="store_true",
                        help="If set (and no fixed filename), save log with UTC timestamp")
    sp_enf.add_argument("--save-local-copy", default="",
                        help="Also scp a local copy of the service file to this path")
    sp_enf.set_defaults(func=cmd_enforce)

    # fetch-keys
    sp_fetch = sub.add_parser("fetch-keys", help="Fetch /tmp/unifiprotectsslkeys.log to a local directory")
    sp_fetch.add_argument("--keylog-dir", required=True, help="Local directory to save the key log")
    sp_fetch.add_argument("--keylog-filename", default="",
                          help="Fixed local filename (omit to make timestamped)")
    sp_fetch.add_argument("--keylog-timestamp", action="store_true",
                          help="If set (and no fixed filename), save with UTC timestamp")
    sp_fetch.set_defaults(func=cmd_fetch_keys)

    # live-capture (pipe to Wireshark or tshark)
    sp_live = sub.add_parser("live-capture", help="Run remote tcpdump and pipe live pcap into local Wireshark/tshark")
    sp_live.add_argument("--iface", default="eth10", help="Remote interface to capture on (default: eth10)")
    sp_live.add_argument("--camera-ip", default="", help="IP of camera to filter for (optional)")
    sp_live.add_argument("--duration", type=int, default=0, help="Remote capture duration in seconds (0 = run until stopped)")
    sp_live.set_defaults(func=cmd_live_capture)

    # capture-to-file
    sp_cap = sub.add_parser("capture-to-file", help="Remote tcpdump to a file, then scp to local outdir")
    sp_cap.add_argument("--iface", default="eth10", help="Remote interface (default: eth10)")
    sp_cap.add_argument("--camera-ip", default="", help="IP of camera to filter for (optional)")
    sp_cap.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
    sp_cap.add_argument("--outdir", required=True, help="Local directory to store the pcap")
    sp_cap.add_argument("--remote-path", default="", help="Explicit remote pcap path (default: /tmp/cap_<ts>.pcapng)")
    sp_cap.add_argument("--keep-remote", action="store_true", help="Keep the remote pcap file (default: delete)")
    sp_cap.set_defaults(func=cmd_capture_to_file)

    # parse-pcap
    sp_parse = sub.add_parser("parse-pcap", help="Decrypt a local pcap using keylog; extract WebSocket payloads")
    sp_parse.add_argument("--pcap", required=True, help="Local pcap path")
    sp_parse.add_argument("--keylog", required=True, help="Local keylog path (unifiprotectsslkeys*.log)")
    sp_parse.add_argument("--outdir", required=True, help="Directory to write parsed output")
    sp_parse.add_argument("--decode-as", default="", help="Comma-separated TLS ports to force as TLS (e.g. 7442,443)")
    sp_parse.set_defaults(func=cmd_parse_pcap)

    # capture-and-parse
    sp_capparse = sub.add_parser("capture-and-parse", help="One-shot: remote capture → fetch → parse with keylog")
    sp_capparse.add_argument("--iface", default="eth10", help="Remote interface (default: eth10)")
    sp_capparse.add_argument("--camera-ip", default="", help="IP of camera to filter for (optional)")
    sp_capparse.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
    sp_capparse.add_argument("--outdir", required=True, help="Local directory to store pcap & parsed output")
    sp_capparse.add_argument("--remote-path", default="", help="Explicit remote pcap path (default: /tmp/cap_<ts>.pcapng)")
    sp_capparse.add_argument("--keep-remote", action="store_true", help="Keep the remote pcap file (default: delete)")
    sp_capparse.add_argument("--keylog", required=True, help="Local keylog path to use for decryption")
    sp_capparse.add_argument("--decode-as", default="", help="Comma-separated TLS ports (e.g. 7442)")
    sp_capparse.set_defaults(func=cmd_capture_and_parse)

    # stream-parse
    sp_stream = sub.add_parser("stream-parse", help="Live: stream remote tcpdump to local tshark, decrypt & parse WebSocket payloads")
    sp_stream.add_argument("--iface", default="eth10", help="Remote interface (default: eth10)")
    sp_stream.add_argument("--camera-ip", default="", help="IP of camera to filter for (optional)")
    sp_stream.add_argument("--duration", type=int, default=0, help="Remote capture duration in seconds (0 = until Ctrl+C)")
    sp_stream.add_argument("--keylog", required=True, help="Local keylog path (unifiprotectsslkeys*.log)")
    sp_stream.add_argument("--outdir", required=True, help="Directory to write parsed frames and combined file")
    sp_stream.add_argument("--save-pcap-stream", default="", help="Optional local file to tee raw pcap stream while parsing")
    sp_stream.add_argument("--decode-as", default="", help="Comma-separated TLS ports to force as TLS (default: 7442)")
    sp_stream.set_defaults(func=cmd_stream_parse)

    # capture-handshake
    sp_hs = sub.add_parser("capture-handshake",
                           help="Capture TLS handshake + WSS upgrade on 7442: start tcpdump, then restart Protect after a short delay; save pcap and parse.")
    sp_hs.add_argument("--iface", default="eth10", help="Remote interface (default: eth10)")
    sp_hs.add_argument("--camera-ip", default="", help="Camera IP to narrow capture (optional)")
    sp_hs.add_argument("--duration", type=int, default=30, help="tcpdump run time (seconds)")
    sp_hs.add_argument("--keylog", required=True, help="Local keylog path")
    sp_hs.add_argument("--outdir", required=True, help="Directory for parsed output")
    sp_hs.add_argument("--save-pcap-stream", required=True, help="Local pcap file to save raw stream")
    sp_hs.add_argument("--decode-as", default="7442", help="Comma-separated TLS ports to force as TLS (default: 7442)")
    sp_hs.add_argument("--pre-restart-delay", type=int, default=2, help="Seconds to wait before restarting Protect")
    sp_hs.set_defaults(func=cmd_capture_handshake)

    args = ap.parse_args()

    # sanity for remote-required commands
    remote_cmds = {
        "check", "enforce", "fetch-keys",
        "live-capture", "capture-to-file",
        "capture-and-parse", "stream-parse",
        "capture-handshake"
    }
    if args.cmd in remote_cmds:
        if not args.host or not args.user:
            print("--host and --user are required for this subcommand")
            sys.exit(2)

    try:
        args.func(args)
    except subprocess.CalledProcessError as e:
        try:
            sys.stderr.write(e.output.decode("utf-8", errors="replace"))
        except Exception:
            pass
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(4)

if __name__ == "__main__":
    main()
