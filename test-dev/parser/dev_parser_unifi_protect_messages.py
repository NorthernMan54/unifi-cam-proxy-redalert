#!/usr/bin/env python3
"""
dev_parser_unifi_protect_messages.py — UniFi Protect stream decoder with live de-duplication

Overview
========
This script automates **remote packet capture, TLS key retrieval, and JSON message decoding**
from UniFi Protect (UDM/UDM-SE). It can run in two modes:

1) Offline mode (default)
   - SSH to controller → start remote tcpdump (multi-port BPF)
   - Detect TLS ServerHello or HTTP 101 Upgrade
   - Fetch `/tmp/unifiprotectsslkeys.log`
   - Stop capture and decode decrypted payloads to JSON via tshark

2) Online (live-unique) mode (`--live-unique`)
   - Keeps remote tcpdump running
   - After handshake + keylog fetch, starts a decrypting monitor that tails the growing PCAP
   - Extracts JSON continuously and **de-duplicates by functionName** (fallback to content hash)
   - Prints a 5-second summary of new vs deduped counts

Key Features
============
- No local tcpdump required (capture runs remotely over SSH)
- TLS 1.3 friendly: keylog is fetched only **after** a fresh handshake
- Multi-port support (e.g., 7441, 7442, 7445, 7550)
- Robust JSON extraction from decrypted WSS/HTTP(S) data
- Append-safe NDJSON output for long runs (24h+)
- 5-second live stats for quick health checks

Service & Camera Restarts
=========================
What the script restarts (controller side)
------------------------------------------
- If `unifi-protect.service`'s ExecStart does **not** include `--tls-keylog <path>`,
  the script patches the unit file and runs:
    `systemctl daemon-reload` and `systemctl restart unifi-protect`
- This restart is **idempotent** and only happens when needed (unless you pass `--no-patch`).
- Impact: a brief Protect outage; cameras will disconnect and then automatically reconnect,
  performing **new TLS handshakes** that write secrets to the keylog file.

When you may need to restart the camera (device side)
-----------------------------------------------------
- If you start a capture **after** a camera already has a long-lived TLS session and you
  never see a new handshake (no “ServerHello” within `--capture-timeout`), you need a fresh
  TLS handshake from that camera. Options:
  - Reboot the camera (Protect UI → Manage → Restart / or power cycle)
  - Temporarily disconnect/reconnect the camera network port
  - Disable/enable the camera in Protect UI (forces re-connect in many cases)
- Other times you might restart the camera:
  - You changed monitored ports or routing and the camera didn't re-establish WSS/HTTPS
  - You want to force immediate renegotiation to resume decryption after topology changes
- If you prefer **not** to disrupt video, just re-run the script and let it wait for the camera's
  next natural reconnect; it will fetch keys only after it observes a fresh handshake.

Safety notes
------------
- Restarting `unifi-protect.service` briefly interrupts recording/alerts; do during a maintenance window.
- Use `--no-patch` to avoid any controller restarts if you've already added `--tls-keylog` permanently.
- The script only fetches the keylog **after** it detects a handshake and a brief settle period, ensuring
  TLS 1.3 secrets are present.

Typical Usage
=============
# --- One-shot offline decode (short run) ---
./dev_parser_unifi_protect_messages.py \
  --host 192.168.0.1 \
  --iface br0 \
  --camera-ip 192.168.0.151 \
  --decode-as 7442,7441,7445,7550 \
  --json-only \
  --msg-limit 200 \
  --json-out ./protect_artifacts/messages.ndjson

# --- Continuous online monitor (live-unique) ---
./dev_parser_unifi_protect_messages.py \
  --host 192.168.0.1 \
  --iface br0 \
  --camera-ip 192.168.0.151 \
  --decode-as 7442,7441,7445,7550 \
  --live-unique \
  --json-only \
  --json-out ./protect_artifacts/unique_live.ndjson \
  --msg-limit 0 \
  --dedupe-window 200000

Optional Flags
==============
--no-patch
    Skip TLS keylog patch/restart if you've already enabled it.
--info-filter 'tls.record.content_type==23'
    Reduce chatter to application data (safer than tcp.segment_data).
--capture-timeout 60
    How long to wait for first handshake before giving up (offline) or continuing (live).
--debug-live-raw 8
    Print the first 8 raw live lines from tshark for quick debugging.

Requirements
============
- Remote: tcpdump on the UDM/UDM-SE
- Local: tshark + ssh/scp (sshpass optional for password auth)

Author
======
Refactored single-file capture and parser tool for UniFi Protect WSS message decoding.
"""

from __future__ import annotations
import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional, Tuple, List, Set, Deque
from collections import deque
import hashlib

# ---------- Constants ----------
SSH_USER = "root"
REMOTE_SERVICE = "/lib/systemd/system/unifi-protect.service"
REMOTE_KEYLOG = "/tmp/unifiprotectsslkeys.log"

# ---------- Small utils ----------
def which(name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(name)

def now_utc_stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())

# ---------- Config ----------
@dataclass(frozen=True)
class Config:
    host: str
    port: int = 22
    key: Optional[str] = None
    keylog_dir: Path = Path("./protect_artifacts")
    keylog_timestamp: bool = False
    iface: str = "br0"
    camera_ip: Optional[str] = None
    ports: Tuple[int, ...] = (7442,)
    capture_timeout_s: int = 60
    post_grace_s: int = 8
    save_pcap: Optional[Path] = None
    json_only: bool = False
    json_out: Optional[Path] = None
    msg_limit: int = 60
    from_filter: Optional[str] = None
    to_filter: Optional[str] = None
    do_patch: bool = True
    settle_keylog_s: float = 2.0  # wait for TLS 1.3 secrets to flush
    live_unique: bool = False
    dedupe_window: int = 100_000  # approx number of recent unique entries to remember
    info_filter: Optional[str] = None  # extra -Y display filter for live monitor (optional)
    debug_live_raw: int = 0  # if >0, print this many raw tshark lines in live mode

    @staticmethod
    def from_cli(args: argparse.Namespace) -> "Config":
        ports = tuple(int(p.strip()) for p in (args.decode_as or "7442").split(",") if p.strip().isdigit())
        return Config(
            host=args.host,
            port=args.port,
            key=args.key,
            keylog_dir=Path(args.keylog_dir),
            keylog_timestamp=args.keylog_timestamp,
            iface=args.iface,
            camera_ip=(args.camera_ip or None),
            ports=ports if ports else (7442,),
            capture_timeout_s=args.capture_timeout,
            post_grace_s=8,
            save_pcap=Path(args.save_pcap) if args.save_pcap else None,
            json_only=args.json_only,
            json_out=Path(args.json_out) if args.json_out else None,
            msg_limit=args.msg_limit,
            from_filter=(args.from_filter or None),
            to_filter=(args.to_filter or None),
            do_patch=(not args.no_patch),
            live_unique=args.live_unique,
            dedupe_window=args.dedupe_window,
            info_filter=(args.info_filter or None),
            debug_live_raw=args.debug_live_raw,
        )

# ---------- SSH client ----------
class SshError(RuntimeError):
    pass

@dataclass(frozen=True)
class SshConfig:
    host: str
    port: int = 22
    key: Optional[str] = None
    password: Optional[str] = None  # UFP_ROOT_PASS if present
    control_persist_s: int = 90
    timeout_s: int = 30

class SshClient:
    def __init__(self, cfg: SshConfig):
        self.cfg = cfg
        self._base_ssh = [
            "ssh",
            "-p", str(cfg.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPersist={cfg.control_persist_s}s",
            "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
        ]
        if cfg.key:
            self._base_ssh += ["-i", cfg.key]

        self._base_scp = [
            "scp",
            "-P", str(cfg.port),
            "-o", "ControlMaster=auto",
            "-o", f"ControlPersist={cfg.control_persist_s}s",
            "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
        ]
        if cfg.key:
            self._base_scp += ["-i", cfg.key]

        self._prefix = []
        if cfg.password and which("sshpass"):
            self._prefix = ["sshpass", "-p", cfg.password]

    def run(self, remote_cmd: str, *, check: bool = True, timeout: Optional[int] = None) -> str:
        cmd = self._prefix + self._base_ssh + [f"{SSH_USER}@{self.cfg.host}", remote_cmd]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout or self.cfg.timeout_s)
            return out.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            if check:
                raise SshError(e.output.decode("utf-8", errors="replace"))
            return e.output.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as e:
            raise SshError("SSH command timed out") from e

    def scp_get(self, remote_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = self._prefix + self._base_scp + [f"{SSH_USER}@{self.cfg.host}:{remote_path}", str(local_path)]
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=self.cfg.timeout_s)
        except subprocess.CalledProcessError as e:
            raise SshError(f"SCP failed: {e}") from e

# ---------- Protect service ops ----------
class ProtectService:
    def __init__(self, ssh: SshClient):
        self.ssh = ssh

    def has_tls_keylog_sentinel(self) -> bool:
        cmd = f"grep -E '^ExecStart=' {REMOTE_SERVICE} 2>/dev/null || true"
        quoted = shlex.quote(cmd)
        out = self.ssh.run(f"sh -lc {quoted}", check=False).strip()
        if not out:
            return False
        return "--tls-keylog" in out

    def patch_execstart_add_tls(self) -> None:
        script = f"""set -e
FILE="{REMOTE_SERVICE}"; TMP="/tmp/unifi-protect.service.$$"
[ -f "$FILE" ]
if grep -E '^ExecStart=' "$FILE" | grep -q -- '--tls-keylog'; then
  systemctl daemon-reload; exit 0
fi
awk 'BEGIN{{p=0}} /^ExecStart=/ && /\\/usr\\/bin\\/node20/ && $0 !~ /--tls-keylog/ {{gsub(/\\/usr\\/bin\\/node20/,"/usr/bin/node20 --tls-keylog {REMOTE_KEYLOG}"); p=1}} {{print}} END{{exit (p?0:5)}}' "$FILE" >"$TMP"
install -m 0644 "$TMP" "$FILE"; rm -f "$TMP"
systemctl daemon-reload
"""
        self.ssh.run(f"sh -lc {shlex.quote(script)}")

    def restart_and_wait(self, timeout_s: int = 60) -> None:
        self.ssh.run("sh -lc 'systemctl restart unifi-protect'")
        end = time.time() + timeout_s
        while time.time() < end:
            state = self.ssh.run("sh -lc 'systemctl is-active unifi-protect || true'", check=False).strip()
            if state == "active":
                return
            time.sleep(1)
        raise SshError("unifi-protect did not become active within timeout")

    def wait_keylog_ready(self, settle_s: float = 2.0, timeout_s: float = 60.0) -> bool:
        """Wait until keylog exists and its size stabilizes for settle_s."""
        script = f"""\
if [ -f {REMOTE_KEYLOG} ]; then
  S=$(stat -c %s {REMOTE_KEYLOG} 2>/dev/null || busybox stat -c %s {REMOTE_KEYLOG} 2>/dev/null || echo 0)
  echo "$S"
else
  echo ""
fi"""
        start = time.time()
        last_size: Optional[int] = None
        last_change = time.time()
        while time.time() - start < timeout_s:
            out = self.ssh.run(f"sh -lc {shlex.quote(script)}", check=False).strip()
            if out.isdigit():
                size = int(out)
                if size > 0:
                    if last_size is None or size != last_size:
                        last_size = size
                        last_change = time.time()
                    else:
                        if time.time() - last_change >= settle_s:
                            return True
            time.sleep(0.5)
        return False

# ---------- Hello detection ----------
@dataclass
class HelloEvent:
    reason: str  # "tls_server_hello" or "http_101_upgrade"
    ts: float = field(default_factory=time.time)
    port: Optional[int] = None
    stream_id: Optional[int] = None

class HelloDetector(threading.Thread):
    """Reads tshark stdout; sets .event when a Hello/Upgrade is detected."""
    def __init__(self, stdout_pipe, event: threading.Event):
        super().__init__(daemon=True)
        self.stdout_pipe = stdout_pipe
        self.event_flag = event
        self.event: Optional[HelloEvent] = None

    def run(self) -> None:
        try:
            while not self.event_flag.is_set():
                line = self.stdout_pipe.readline()
                if not line:
                    break
                text = line.strip()
                if not text:
                    continue
                if "Server Hello" in text or "ServerHello" in text:
                    self.event = HelloEvent(reason="tls_server_hello")
                    self.event_flag.set()
                    break
                if "101 Switching Protocols" in text or "Upgrade: websocket" in text or "WebSocket" in text:
                    self.event = HelloEvent(reason="http_101_upgrade")
                    self.event_flag.set()
                    break
        except Exception:
            pass

# ---------- Capture coordinator ----------
class CaptureCoordinator:
    def __init__(self, cfg: Config, ssh: SshClient):
        self.cfg = cfg
        self.ssh = ssh
        self.ssh_proc: Optional[subprocess.Popen] = None
        self.tshark_proc: Optional[subprocess.Popen] = None
        self.forwarder: Optional[threading.Thread] = None
        self.hello_seen = threading.Event()
        self.detector: Optional[HelloDetector] = None
        self._pcap_path = cfg.save_pcap or (cfg.keylog_dir / "handshake_capture.pcap")

    def _build_bpf(self) -> str:
        port_expr = " or ".join(f"port {p}" for p in self.cfg.ports)
        bpf = f"({port_expr})"
        if self.cfg.camera_ip:
            bpf += f" and (src host {self.cfg.camera_ip} or dst host {self.cfg.camera_ip})"
        return bpf

    def start(self) -> None:
        if not which("tshark"):
            raise RuntimeError("tshark not found on PATH")
        bpf = self._build_bpf()
        tcpdump_cmd = f"sudo tcpdump -U -s0 -i {self.cfg.iface} -w - '{bpf}'"
        ssh_cmd = self.ssh._prefix + self.ssh._base_ssh + [f"{SSH_USER}@{self.ssh.cfg.host}", f"sh -lc {shlex.quote(tcpdump_cmd)}"]

        decode_args: list[str] = []
        for p in self.cfg.ports:
            # map to TLS for hello detection
            decode_args += ["-d", f"tcp.port=={p},tls"]

        tshark_cmd = ["tshark", "-r", "-", "-l", "-n"] + decode_args + [
            "-T", "fields", "-e", "_ws.col.Info",
            "-Y", 'tls.handshake.type == 2 or (http.response.code == 101 && http.upgrade == "websocket")'
        ]

        self._pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.tshark_proc = subprocess.Popen(
            tshark_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        assert self.ssh_proc.stdout and self.tshark_proc.stdin

        # Forwarder: bytes → pcap file + tshark stdin
        def _forward():
            with open(self._pcap_path, "wb") as pcap_out:
                try:
                    while True:
                        chunk = self.ssh_proc.stdout.read(65536)  # type: ignore
                        if not chunk:
                            break
                        pcap_out.write(chunk)
                        try:
                            self.tshark_proc.stdin.buffer.write(chunk)  # type: ignore[attr-defined]
                            self.tshark_proc.stdin.flush()
                        except (BrokenPipeError, ValueError):
                            break
                finally:
                    try:
                        if self.tshark_proc and self.tshark_proc.stdin:
                            self.tshark_proc.stdin.close()
                    except Exception:
                        pass

        self.forwarder = threading.Thread(target=_forward, daemon=True)
        self.forwarder.start()

        # Hello detector thread
        assert self.tshark_proc.stdout
        self.detector = HelloDetector(self.tshark_proc.stdout, self.hello_seen)
        self.detector.start()

    def wait_for_hello(self, timeout_s: int) -> Optional[HelloEvent]:
        if not self.ssh_proc or not self.tshark_proc or not self.detector:
            raise RuntimeError("Capture not started")
        if self.hello_seen.wait(timeout_s):
            return self.detector.event
        return None

    def stop_gracefully(self) -> None:
        # Stop tcpdump cleanly on remote with SIGINT to avoid truncation
        try:
            pattern = f"tcpdump -U -s0 -i {self.cfg.iface} "
            self.ssh.run(f"sh -lc {shlex.quote(f'pkill -INT -f {pattern} || true')}", check=False)
        except Exception:
            pass

        try:
            if self.forwarder:
                self.forwarder.join(timeout=3)
        except Exception:
            pass

        for proc in (self.tshark_proc, self.ssh_proc):
            if not proc:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def pcap_path(self) -> Path:
        return self._pcap_path

# ---------- Keylog manager ----------
class KeylogManager:
    def __init__(self, cfg: Config, ssh: SshClient, svc: ProtectService):
        self.cfg = cfg
        self.ssh = ssh
        self.svc = svc
        self._fetched = False
        self._local_path: Optional[Path] = None

    def _build_local_path(self) -> Path:
        self.cfg.keylog_dir.mkdir(parents=True, exist_ok=True)
        if self.cfg.keylog_timestamp:
            return self.cfg.keylog_dir / f"unifiprotectsslkeys_{now_utc_stamp()}.log"
        return self.cfg.keylog_dir / "unifiprotectsslkeys_latest.log"

    def fetch_once_after_hello(self) -> Path:
        if self._fetched and self._local_path:
            return self._local_path
        ok = self.svc.wait_keylog_ready(settle_s=self.cfg.settle_keylog_s, timeout_s=60)
        if not ok:
            raise SshError("Key log did not appear or settle after handshake")
        local = self._build_local_path()
        self.ssh.scp_get(REMOTE_KEYLOG, local)
        self._fetched = True
        self._local_path = local
        return local

# ---------- JSON extraction ----------
class MessageExtractor:
    """Brace-balanced JSON scanner with simple framing tolerance."""
    @staticmethod
    def scan(text: str) -> Iterator[dict]:
        buf: List[str] = []
        depth = 0
        for ch in text:
            if depth == 0:
                if ch != "{":
                    continue
                buf = ["{"]
                depth = 1
                continue
            buf.append(ch)
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blob = "".join(buf)
                    try:
                        yield json.loads(blob)
                    except Exception:
                        pass
                    buf = []

# ---------- Decoder (offline) ----------
class Decoder:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _decode_args(self) -> list[str]:
        args: list[str] = []
        for p in self.cfg.ports:
            args += ["-d", f"tcp.port=={p},tls"]
        return args

    def candidate_streams(self, pcap: Path, keylog: Path) -> list[int]:
        base = ["tshark", "-r", str(pcap), "-n",
                "-o", f"tls.keylog_file:{keylog}",
                "-o", "tcp.desegment_tcp_streams:true",
                "-o", "tls.desegment_ssl_records:true"] + self._decode_args()
        for df in [
            "tls.handshake.type==1 || tls.handshake.type==2",
            "ssl.handshake.type==1 || ssl.handshake.type==2",
            "tls", "ssl",
        ]:
            cmd = base + ["-Y", df, "-T", "fields", "-e", "tcp.stream"]
            out = subprocess.run(cmd, capture_output=True, text=True).stdout
            seen = set()
            streams = []
            for line in out.splitlines():
                s = line.strip()
                if s.isdigit() and s not in seen:
                    seen.add(s); streams.append(int(s))
            if streams:
                return streams
        return list(range(0, 8))

    def decode_first_messages(self, pcap: Path, keylog: Path, limit: int,
                              json_only: bool, from_filter: Optional[str], to_filter: Optional[str]) -> Iterator[dict]:
        streams = self.candidate_streams(pcap, keylog)
        printed = 0
        for stream in streams:
            if printed >= limit:
                break
            follow_cmd = [
                "tshark", "-r", str(pcap), "-q", "-z", f"follow,tls,ascii,{stream}",
                "-n",
                "-o", f"tls.keylog_file:{keylog}",
                "-o", "tcp.desegment_tcp_streams:true",
                "-o", "tls.desegment_ssl_records:true",
            ] + self._decode_args()
            proc = subprocess.Popen(follow_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                collecting = False
                assert proc.stdout
                for line in proc.stdout:
                    if printed >= limit:
                        break
                    if line.startswith("==================================================================="):
                        collecting = not collecting
                        continue
                    if not collecting:
                        continue
                    if json_only:
                        for obj in MessageExtractor.scan(line):
                            if from_filter and obj.get("from") != from_filter:
                                continue
                            if to_filter and obj.get("to") != to_filter:
                                continue
                            yield obj
                            printed += 1
                            if printed >= limit:
                                break
                    else:
                        a = line.find("{"); b = line.rfind("}")
                        if a != -1 and b > a:
                            try:
                                obj = json.loads(line[a:b+1])
                                if from_filter and obj.get("from") != from_filter:
                                    continue
                                if to_filter and obj.get("to") != to_filter:
                                    continue
                                yield obj
                                printed += 1
                            except Exception:
                                pass
            finally:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

# ---------- Live monitor: replay + follow a growing PCAP ----------
class LiveJsonMonitor:
    """
    Starts a decrypting tshark that reads from stdin (-r -).
    A feeder thread streams bytes from the growing PCAP file starting at byte 0,
    then keeps following new bytes as the file grows.
    We parse tshark stdout in near-real time, extract JSON, and de-duplicate by functionName.

    Prints a 5s summary: "new" (written) vs "deduped" (filtered), plus running totals.
    """
    def __init__(self, cfg: Config, pcap_path: Path, keylog_path: Path):
        self.cfg = cfg
        self.pcap_path = pcap_path
        self.keylog_path = keylog_path
        self.tshark: Optional[subprocess.Popen] = None
        self.feeder: Optional[threading.Thread] = None
        self.stop_ev = threading.Event()

        # de-dup window (approximate): keep last N distinct function names (or hashes when no fn)
        self.seen_window: int = cfg.dedupe_window
        self.seen_funcs: Set[str] = set()
        self.seen_q: Deque[str] = deque()

        # stats
        self.stats_interval_s = 5.0
        self.total_new = 0
        self.total_deduped = 0
        self.last_report_ts = time.time()
        self.w_new_5s = 0
        self.w_deduped_5s = 0

        self.sink = MessageSink(self.cfg.json_out)

    def _remember(self, fn_or_hash: str) -> None:
        self.seen_funcs.add(fn_or_hash)
        self.seen_q.append(fn_or_hash)
        if len(self.seen_q) > self.seen_window:
            old = self.seen_q.popleft()
            self.seen_funcs.discard(old)

    def _decode_args(self) -> list[str]:
        args: list[str] = []
        for p in self.cfg.ports:
            args += ["-d", f"tcp.port=={p},tls"]
        return args

    def _maybe_report(self, force: bool = False) -> None:
        now = time.time()
        if force or (now - self.last_report_ts) >= self.stats_interval_s:
            print(f"[live/stats] +{int(now - self.last_report_ts)}s: "
                  f"new={self.w_new_5s}, deduped={self.w_deduped_5s} | "
                  f"totals: new={self.total_new}, deduped={self.total_deduped}, "
                  f"unique_keys={len(self.seen_funcs)}")
            self.last_report_ts = now
            self.w_new_5s = 0
            self.w_deduped_5s = 0

    def start(self) -> None:
        # tshark reading from stdin; read decrypted application data
        tshark_cmd = [
            "tshark", "-r", "-", "-l", "-n",
            "-o", f"tls.keylog_file:{self.keylog_path}",
            "-o", "tcp.desegment_tcp_streams:true",
            "-o", "tls.desegment_ssl_records:true",
        ] + self._decode_args()

        if self.cfg.info_filter:
            tshark_cmd += ["-Y", self.cfg.info_filter]

        # Ask for several likely payload fields; tab-separate columns explicitly
        tshark_cmd += [
            "-T", "fields", "-E", "separator=\t",
            "-e", "tcp.segment_data",  # hex (often populated)
            "-e", "data.text",         # printable
            "-e", "data.data",         # hex (common on some builds)
            "-e", "tls.app_data",      # hex (sometimes here)
        ]

        self.tshark = subprocess.Popen(
            tshark_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,  # stdout is text; stdin will use .buffer for binary
            bufsize=1
        )
        assert self.tshark.stdin and self.tshark.stdout

        # Feeder thread: stream PCAP bytes to tshark stdin, then follow growth
        def _feeder():
            try:
                with open(self.pcap_path, "rb") as f:
                    while not self.stop_ev.is_set():
                        chunk = f.read(1024 * 256)
                        if chunk:
                            try:
                                self.tshark.stdin.buffer.write(chunk)  # type: ignore[attr-defined]
                                self.tshark.stdin.flush()
                            except (BrokenPipeError, ValueError):
                                break
                            continue
                        time.sleep(0.25)  # wait for file to grow
            finally:
                try:
                    if self.tshark and self.tshark.stdin:
                        self.tshark.stdin.close()
                except Exception:
                    pass

        self.feeder = threading.Thread(target=_feeder, daemon=True)
        self.feeder.start()

        # Consumer thread: parse tshark stdout for JSON, de-dup, and report stats
        def _consumer():
            try:
                assert self.tshark and self.tshark.stdout
                count = 0
                dbg_left = max(0, int(self.cfg.debug_live_raw))
                for raw_line in self.tshark.stdout:
                    if self.stop_ev.is_set():
                        break
                    if dbg_left > 0:
                        print(f"[live/raw] {raw_line[:200]!r}")
                        dbg_left -= 1

                    line = raw_line.rstrip("\n")
                    if not line:
                        self._maybe_report()
                        continue

                    cols = line.split("\t")  # [seg_hex, text, data_hex, app_hex]
                    chunks: List[str] = []

                    # text column as-is
                    if len(cols) > 1 and cols[1]:
                        chunks.append(cols[1])

                    # decode hex-ish columns
                    for idx in (0, 2, 3):
                        if idx < len(cols):
                            s = cols[idx].strip()
                            if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
                                try:
                                    chunks.append(bytes.fromhex(s).decode("utf-8", "ignore"))
                                except Exception:
                                    pass

                    wrote_any = False
                    deduped_here = 0

                    for chunk in chunks:
                        for obj in MessageExtractor.scan(chunk):
                            if self.cfg.from_filter and obj.get("from") != self.cfg.from_filter:
                                continue
                            if self.cfg.to_filter and obj.get("to") != self.cfg.to_filter:
                                continue

                            fn = obj.get("functionName")
                            key: str
                            if fn:
                                key = f"fn:{fn}"
                            else:
                                blob = json.dumps(obj, sort_keys=True, ensure_ascii=False)
                                key = "h:" + hashlib.sha1(blob.encode("utf-8")).hexdigest()

                            if key in self.seen_funcs:
                                deduped_here += 1
                                continue

                            self._remember(key)
                            self.sink.write(obj)
                            wrote_any = True
                            self.total_new += 1
                            self.w_new_5s += 1
                            count += 1
                            if self.cfg.msg_limit and count >= self.cfg.msg_limit:
                                self.stop_ev.set()
                                break
                        if self.stop_ev.is_set():
                            break

                    self.total_deduped += deduped_here
                    self.w_deduped_5s += deduped_here

                    # periodic stats line every ~5s
                    self._maybe_report()

                # final report on exit
                self._maybe_report(force=True)
            finally:
                self.sink.close()

        threading.Thread(target=_consumer, daemon=True).start()

    def stop(self) -> None:
        self.stop_ev.set()
        try:
            if self.feeder:
                self.feeder.join(timeout=2)
        except Exception:
            pass
        if self.tshark:
            try:
                self.tshark.terminate()
                self.tshark.wait(timeout=3)
            except Exception:
                try:
                    self.tshark.kill()
                except Exception:
                    pass

# ---------- Sinks ----------
class MessageSink:
    def __init__(self, ndjson_path: Optional[Path]):
        self.path = ndjson_path
        self._fh = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a", encoding="utf-8")  # append for long runs

    def write(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        print(line)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.flush()
                self._fh.close()
            finally:
                self._fh = None

# ---------- Orchestration ----------
class App:
    def __init__(self, cfg: Config):
        password = os.getenv("UFP_ROOT_PASS")
        self.ssh = SshClient(SshConfig(host=cfg.host, port=cfg.port, key=cfg.key, password=password, timeout_s=120))
        self.cfg = cfg
        self.svc = ProtectService(self.ssh)
        self.keymgr = KeylogManager(cfg, self.ssh, self.svc)
        self.decoder = Decoder(cfg)

    def run_full_once(self) -> int:
        # 1) optional service patch (idempotent)
        if self.cfg.do_patch and not self.svc.has_tls_keylog_sentinel():
            print("[svc] Patching ExecStart with --tls-keylog …")
            self.svc.patch_execstart_add_tls()
            print("[svc] Restarting Protect …")
            self.svc.restart_and_wait(timeout_s=60)
        else:
            print("[svc] TLS keylog already present or patching disabled.")

        # 2) start capture (remote tcpdump → local hello detector, and tee to file)
        cap = CaptureCoordinator(self.cfg, self.ssh)
        print("[capture] Starting remote tcpdump + local hello detector …")
        cap.start()

        # 3) wait for hello
        event = cap.wait_for_hello(self.cfg.capture_timeout_s)
        if not event:
            print("[capture] Timeout waiting for TLS ServerHello/HTTP 101 Upgrade.")
        else:
            print(f"[capture] Detected handshake: {event.reason}")

        pcap_path = cap.pcap_path()
        print(f"[capture] PCAP (growing) → {pcap_path}")

        if not event:
            cap.stop_gracefully()
            print("[fetch] Skipping keylog fetch (no hello detected).")
            return 2

        # 4) allow a few more packets (optional)
        if self.cfg.post_grace_s > 0:
            time.sleep(self.cfg.post_grace_s)

        # 5) JIT fetch keylog (after hello)
        print("[fetch] Waiting for key log to settle and fetching once …")
        keylog_local = self.keymgr.fetch_once_after_hello()
        print(f"[fetch] Key log saved → {keylog_local}")

        # 6) If live-unique: start live decrypt monitor (keep tcpdump running!)
        if self.cfg.live_unique:
            if not self.cfg.json_out:
                print("ERROR: --live-unique requires --json-out to write NDJSON.")
                cap.stop_gracefully()
                return 1
            print("[live] Starting decrypting live monitor (replay + follow) …")
            monitor = LiveJsonMonitor(self.cfg, pcap_path, keylog_local)
            monitor.start()
            try:
                # Run until msg_limit reached or interrupted
                while True:
                    if monitor.stop_ev.is_set():
                        break
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("[live] Interrupted; stopping …")
            finally:
                monitor.stop()
                cap.stop_gracefully()
            return 0

        # 7) Else: stop capture and decode offline once
        cap.stop_gracefully()

        print(f"[decode] Extracting up to {self.cfg.msg_limit} JSON messages …")
        sink = MessageSink(self.cfg.json_out)
        try:
            count = 0
            for obj in self.decoder.decode_first_messages(
                pcap_path,
                keylog_local,
                limit=self.cfg.msg_limit,
                json_only=self.cfg.json_only,
                from_filter=self.cfg.from_filter,
                to_filter=self.cfg.to_filter,
            ):
                sink.write(obj)
                count += 1
            print(f"[decode] Printed {count} JSON messages.")
        finally:
            sink.close()

        return 0

# ---------- CLI ----------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Unified multi-port TLS capture with JIT key fetch & JSON decode (single-file).")
    ap.add_argument("--host", required=True, help="UDM/UDM SE IP/hostname")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--key", default=None, help="SSH private key (optional)")
    ap.add_argument("--keylog-dir", default="./protect_artifacts", help="Local directory to store key log & artifacts")
    ap.add_argument("--keylog-timestamp", action="store_true", help="Save key log with UTC timestamp in filename")

    ap.add_argument("--iface", default="br0", help="Remote capture interface (default: br0)")
    ap.add_argument("--camera-ip", default="", help="Optional camera IP to narrow capture")
    ap.add_argument("--decode-as", default="7442", help="Comma-separated ports to decode as TLS (default: 7442)")
    ap.add_argument("--capture-timeout", type=int, default=60, help="Seconds to wait for hello (default: 60)")
    ap.add_argument("--save-pcap", default="", help="Optional output pcap path (default: keylog-dir/handshake_capture.pcap)")

    ap.add_argument("--json-only", action="store_true", help="Print only valid JSON objects")
    ap.add_argument("--json-out", default="", help="Optional NDJSON output path")
    ap.add_argument("--msg-limit", type=int, default=60, help="Max JSON messages to print")
    ap.add_argument("--from-filter", default="", help='Only keep messages with this "from" value')
    ap.add_argument("--to-filter", default="", help='Only keep messages with this "to" value')

    ap.add_argument("--no-patch", action="store_true", help="Do not patch/restart unifi-protect (assume already patched)")

    # Live mode options
    ap.add_argument("--live-unique", action="store_true", help="After hello+keylog, decrypt and stream only UNIQUE JSON messages (replay+follow PCAP).")
    ap.add_argument("--dedupe-window", type=int, default=100_000, help="Approximate number of recent unique items to remember (default: 100k).")
    ap.add_argument("--info-filter", default="", help="Optional tshark -Y display filter for live monitor (e.g., 'tls.record.content_type==23').")
    ap.add_argument("--debug-live-raw", type=int, default=0, help="Print this many raw lines from live tshark for debugging.")

    return ap

def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    cfg = Config.from_cli(args)
    app = App(cfg)
    try:
        return app.run_full_once()
    except KeyboardInterrupt:
        print("Interrupted.")
        return 130
    except SshError as e:
        print(str(e).rstrip())
        return 2
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
