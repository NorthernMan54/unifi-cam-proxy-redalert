#!/usr/bin/env python3
"""
ufp_capture_refactor.py  —  single-file, class-based refactor

End-state goals implemented:
- One remote tcpdump (multi-port BPF), streamed to local
- Local tshark detects first TLS ServerHello or HTTP 101 Upgrade
- Fetch TLS key log **only after** hello (TLS 1.3 friendly), with brief settle
- Decode JSON messages from decrypted streams (balanced-brace extractor)
- No file hashing; no repeated key pulls (optional refresh hook left for future)
- Safer process lifecycle; fewer SSH round-trips via batched shell snippets

Requires: ssh/scp, (optionally) sshpass, tcpdump on remote, tshark locally.
"""

from __future__ import annotations
import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional, Tuple

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
        # Build the remote grep once; no nested f-strings.
        cmd = f"grep -E '^ExecStart=' {REMOTE_SERVICE} 2>/dev/null || true"
        quoted = shlex.quote(cmd)
        out = self.ssh.run(f"sh -lc {quoted}", check=False).strip()

        # If we couldn't read the ExecStart line, play it safe and say "not present".
        if not out:
            return False

        # Return True only if the tls keylog flag is on the ExecStart line.
        return "--tls-keylog" in out

    def patch_execstart_add_tls(self) -> None:
        # Single script to patch and daemon-reload; idempotent
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
                # Simple heuristic based on Info column
                if "Server Hello" in text or "ServerHello" in text:
                    self.event = HelloEvent(reason="tls_server_hello")
                    self.event_flag.set()
                    break
                if "101 Switching Protocols" in text or "Upgrade: websocket" in text or "WebSocket" in text:
                    self.event = HelloEvent(reason="http_101_upgrade")
                    self.event_flag.set()
                    break
        except Exception:
            # Don't crash the process on parser issues
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
            decode_args += ["-d", f"tcp.port=={p},ssl"]  # decode as TLS for hello detection

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
                            # tshark stdin is text mode; write raw via buffer
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

        # Join forwarder
        try:
            if self.forwarder:
                self.forwarder.join(timeout=3)
        except Exception:
            pass

        # Tear down local processes
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

# ---------- Keylog manager (JIT fetch) ----------
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
        # Short settle window to ensure TLS1.3 secrets are written
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
        buf: list[str] = []
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

# ---------- Decoder ----------
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
        # Try to discover streams with TLS presence; fallback to 0..7
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
                        # Best-effort inline extraction
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

# ---------- Sinks ----------
class MessageSink:
    def __init__(self, ndjson_path: Optional[Path]):
        self.path = ndjson_path
        self._fh = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "w", encoding="utf-8")

    def write(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        print(line)
        if self._fh:
            self._fh.write(line + "\n")

    def close(self) -> None:
        if self._fh:
            self._fh.flush()
            self._fh.close()
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

        # 2) start capture
        cap = CaptureCoordinator(self.cfg, self.ssh)
        print("[capture] Starting remote tcpdump + local hello detector …")
        cap.start()

        # 3) wait for hello
        event = cap.wait_for_hello(self.cfg.capture_timeout_s)
        if not event:
            print("[capture] Timeout waiting for TLS ServerHello/HTTP 101 Upgrade.")
        else:
            print(f"[capture] Detected handshake: {event.reason}")

        # 4) stop capture (graceful)
        if event:
            time.sleep(max(0, self.cfg.post_grace_s))  # allow a few more packets
        cap.stop_gracefully()
        pcap_path = cap.pcap_path()
        print(f"[capture] PCAP saved → {pcap_path}")

        # 5) JIT fetch keylog (after hello)
        if not event:
            print("[fetch] Skipping keylog fetch (no hello detected).")
            return 2
        print("[fetch] Waiting for key log to settle and fetching once …")
        keylog_local = self.keymgr.fetch_once_after_hello()
        print(f"[fetch] Key log saved → {keylog_local}")

        # 6) Decode & print first messages
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
