#!/usr/bin/env python3
"""
dev_parser_unifi_protect_messages.py

Remotely manage UniFi Protect service TLS key logging on a UDM/UDM SE.

How to use

Check only (no changes):

python3 dev_parser_unifi_protect_messages.py \
  --host 192.168.0.1 --user root \
  check

Enforce the modification and restart, then verify, and fetch the keys file to a local folder:

python3 dev_parser_unifi_protect_messages.py \
  --host 192.168.0.1 --user root \
  enforce \
  --keylog-dir ./protect_artifacts \
  --keylog-timestamp \
  --save-local-copy ./protect_artifacts/unifi-protect.service.current \
  --remote-backup-path /lib/systemd/system/unifi-protect.service.bak

Fetch latest keys later (periodically, e.g. via cron):
*** not tested

python3 dev_parser_unifi_protect_messages.py \
  --host 192.168.0.1 --user root \
  fetch-keys \
  --keylog-dir ./protect_keys \
  --keylog-timestamp

Features:
- Check if /lib/systemd/system/unifi-protect.service contains the --tls-keylog flag
- If missing, patch ExecStart to add: --tls-keylog /tmp/unifiprotectsslkeys.log
- Reload systemd, restart unifi-protect, and verify the service is active
- Verify the modification is present after restart
- Fetch /tmp/unifiprotectsslkeys.log to your local machine (timestamped or fixed name)
- Optional: save a *local* copy of the service file for diff/reference

Requires:
- Python 3.7+
- Local `ssh` and `scp` available on PATH
- SSH access to the UDM (root recommended)

Exit codes:
  0 = success
  1 = verification failure or modification failed
  2 = SSH/SCP failure
  3 = remote file missing
  4 = other error
"""

import argparse
import os
import shlex
import subprocess
import sys
from datetime import datetime

REMOTE_SERVICE = "/lib/systemd/system/unifi-protect.service"
TLS_SENTINEL = "--tls-keylog /tmp/unifiprotectsslkeys.log"
REMOTE_KEYLOG = "/tmp/unifiprotectsslkeys.log"


# ---------------- SSH helpers ----------------

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

def ssh_common_opts(port=22, key=None):
    # Reuse a single control connection for N seconds
    return [
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=90s",
        "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
    ] + (["-i", key] if key else [])

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
    # Build remote grep command safely
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

    # Fallback with awk
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
    Safely patch ExecStart to insert TLS_SENTINEL immediately after /usr/bin/node20
    - Writes to /tmp tmpfile then moves back
    - Preserves permissions (chmod 644) and ownership root:root
    - Idempotent: only patches when --tls-keylog is not already present
    """
    remote_script = r'''
set -e
FILE="''' + REMOTE_SERVICE + r'''"
TMP="/tmp/unifi-protect.service.$$"
# sanity
[ -f "$FILE" ]

# Only modify if ExecStart lacks the tls flag
if grep -E '^ExecStart=' "$FILE" | grep -q -- '--tls-keylog'; then
  echo "Already contains --tls-keylog"
  exit 0
fi

# Create transformed temp file
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
  if (patched==0) {
    # If we never saw a matching ExecStart, return error so caller knows
    exit 5
  }
}
' "$FILE" > "$TMP"

# Move into place atomically-ish
# Save mode/owner, then set properly
install -m 0644 "$TMP" "$FILE"
rm -f "$TMP"

# Done
'''
    try:
        out = run_ssh(
            user, host,
            f"sh -lc {shlex.quote(remote_script)}",
            port, key, check=True
        )
        return True, out
    except subprocess.CalledProcessError as e:
        # awk END exit 5 -> missing ExecStart pattern
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
    # Ensure remote file exists (won't fail the scp with ugly message)
    exists = run_ssh(
        user, host,
        f"sh -lc {shlex.quote(f'[ -f {REMOTE_KEYLOG} ] && echo YES || echo NO')}",
        port, key, check=True
    ).strip() == "YES"
    if not exists:
        raise FileNotFoundError(f"{REMOTE_KEYLOG} not found on remote.")
    scp_download(user, host, REMOTE_KEYLOG, local_path, port, key)
    return local_path


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
    # 1) Check
    if not remote_file_exists(args.user, args.host, REMOTE_SERVICE, args.port, args.key):
        print(f"Remote file missing: {REMOTE_SERVICE}")
        sys.exit(3)
    present, line = has_tls_sentinel(args.user, args.host, REMOTE_SERVICE, args.port, args.key)
    print("Before:", line or "(not found)")
    if present:
        print("TLS keylog already present; no edit needed.")
    else:
        # 2) Backup original (once)
        backup = backup_service_if_needed(args.user, args.host, args.port, args.key, args.remote_backup_path)
        print(f"Ensured remote backup at: {backup}")
        # 3) Patch
        ok, msg = patch_execstart_to_add_tls(args.user, args.host, args.port, args.key)
        if not ok:
            print(msg)
            sys.exit(1)
        print("Patched ExecStart to include TLS key logging.")

    # 4) Reload & restart
    print("Reloading systemd and restarting unifi-protect...")
    try:
        daemon_reload_and_restart(args.user, args.host, args.port, args.key)
    except subprocess.CalledProcessError:
        print("Failed to restart unifi-protect.")
        sys.exit(2)

    # 5) Verify service up
    print("Waiting for service to become active...")
    if not wait_active(args.user, args.host, args.port, args.key, args.start_timeout):
        print("Service did not become active within timeout.")
        sys.exit(1)
    print("Service is active.")

    # 6) Verify modification present
    present, line = has_tls_sentinel(args.user, args.host, REMOTE_SERVICE, args.port, args.key)
    print("After :", line or "(not found)")
    if not present:
        print("ERROR: TLS keylog flag not present after restart.")
        sys.exit(1)
    print("Verified TLS keylog flag present.")

    # 7) Optionally fetch keylog
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

    # 8) Optionally save a local copy of the service file
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


# ---------------- Main ----------------

def main():
    ap = argparse.ArgumentParser(description="UDM Protect TLS keylog enforcer & fetcher (remote SSH)")
    ap.add_argument("--host", required=True, help="UDM IP/hostname")
    ap.add_argument("--user", required=True, help="SSH user (root recommended)")
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
    sp_fetch = sub.add_parser("fetch-keys", help="Just fetch /tmp/unifiprotectsslkeys.log to a local directory")
    sp_fetch.add_argument("--keylog-dir", required=True, help="Local directory to save the key log")
    sp_fetch.add_argument("--keylog-filename", default="",
                          help="Fixed local filename (omit to make timestamped)")
    sp_fetch.add_argument("--keylog-timestamp", action="store_true",
                          help="If set (and no fixed filename), save with UTC timestamp")
    sp_fetch.set_defaults(func=cmd_fetch_keys)

    args = ap.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError:
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(4)

if __name__ == "__main__":
    main()