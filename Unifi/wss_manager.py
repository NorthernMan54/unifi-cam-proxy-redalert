import asyncio
import json
import logging
import os
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Tuple
import websockets  # type: ignore
from websockets.client import WebSocketClientProtocol  # type: ignore
from Unifi.drivers.camera_factory import build_camera_driver

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_hostport(hostport: str) -> Tuple[str, int]:
    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return host, 7442
    return hostport, 7442


class WssManager(threading.Thread):
    """
    Hello-only WSS client:
      - connects
      - sends ubnt_avclient_hello
      - logs everything else (no responses)
    Expects settings:
      settings["mgmt.token"] (str)
      settings["mgmt.connectionHost"] like "192.168.0.1:7442"
      settings["mac"], settings["host"], settings["firmwareVersion"], settings["sysid"]
    """

    USE_SECURE_TRANSFER_SUBPROTOCOL = True  # keep what worked for you

    def __init__(self, settings, token_event: threading.Event, stop_event: threading.Event, logger: logging.Logger):
        super().__init__(daemon=True, name="WSSManager")
        self.settings = settings
        self.token_event = token_event
        self.stop_event = stop_event
        self.log = logger
        self._msg_id = 0
        self.driver = build_camera_driver(settings, logger)
        SNAPSHOT_DEBUG_DIR = "/workspaces/unifi-cam-proxy/debug_snaps"  # static path
        MAX_SNAPSHOT_FILES = 5
        self._snapshot_debug = os.getenv("SNAPSHOT_DEBUG", "").strip().lower() in {"true"}
        self._snapshot_debug_dir = SNAPSHOT_DEBUG_DIR               # static dir
        self._snapshot_keep = MAX_SNAPSHOT_FILES                    # max files to keep

        '''
        ENV overrides
        WSS_LOG_ONLY="GetRequest,ChangeIspSettings" → only log these fns
        WSS_SILENCE="NetworkStatus,GetSystemStats" → additionally silence these
        WSS_THROTTLE=60 → only log NetworkStatus/GetSystemStats at most once per 60s
        SNAPSHOT_DEBUG=True → set to True to enable snapshot DIR
        '''
        self._last_log_ts = {}
        self._throttle_secs = float(os.getenv("WSS_THROTTLE", "0"))  # 0 = no throttle


        # default noisy functions to suppress unless explicitly allowed
        self._default_noisy = {
            "NetworkStatus",
            "GetSystemStats",
            "ubnt_avclient_paramAgreement",
            "ChangeOsdSettings",
            "ChangeSoundLedSettings",
            "ChangeTalkbackSettings",
            "ChangeAnalyticsSettings",
            "ChangeDeviceSettings",
            "ChangeVideoSettings",
            "ChangeIspSettings",
            "UpdateUsernamePassword",
        }

        # env-based controls
        self._only = {s.strip() for s in os.getenv("WSS_LOG_ONLY", "").split(",") if s.strip()}
        self._silence = {s.strip() for s in os.getenv("WSS_SILENCE", "").split(",") if s.strip()}

        self.handlers = {
                    # Core handshake/maintenance
                    "ubnt_avclient_paramAgreement": self._on_param_agreement,
                    "ubnt_avclient_timeSync": self._on_time_sync,
                    "GetSystemStats": self._on_get_system_stats,
                    "NetworkStatus": self._on_network_status,
        
                    # Settings
                    "ChangeVideoSettings": self._on_change_video_settings,   # driver-backed
                    "ChangeIspSettings":   self._on_change_isp_settings,     # driver-backed
                    "ChangeOsdSettings": self._on_change_osd_settings,
                    "ChangeSoundLedSettings": self._on_change_sound_led_settings,
                    "ChangeTalkbackSettings": self._on_change_talkback_settings,
                    "ChangeAnalyticsSettings": self._on_change_analytics_settings,
                    "ChangeDeviceSettings": self._on_change_device_settings,
                    "UpdateUsernamePassword": self._on_update_username_password,
                    "ChangeClarityZones": self._on_change_clarity_zones,

                    # Misc
                    "AnalyticsTest": self._on_analytics_test,
                    "GetRequest": self._on_get_request,   # snapshot
                    "UpdateFaceDBRequest": self._on_update_face_db_request,
                }

    # --------- log filtering + throttling helpers ---------

    def _should_log(self, fn: str) -> bool:
        if not fn:
            return True
        if self._only:
            return fn in self._only
        if fn in self._silence or fn in self._default_noisy:
            return False
        return True

    def _throttle_ok(self, fn: str) -> bool:
        # Only throttle the periodic status polls by default
        if self._throttle_secs <= 0 or fn not in {"NetworkStatus", "GetSystemStats"}:
            return True
        now = time.monotonic()
        last = self._last_log_ts.get(fn, 0.0)
        if now - last >= self._throttle_secs:
            self._last_log_ts[fn] = now
            return True
        return False

    def _log_rx(self, fn: str, raw: str):
        if self._should_log(fn) and self._throttle_ok(fn):
            self.log.debug("WSS <- %s: %s", fn or "?", raw)

    def _log_tx(self, fn: str, raw: str):
        if self._should_log(fn) and self._throttle_ok(fn):
            self.log.debug("WSS -> %s: %s", fn or "?", raw)

    # ---------------- Snap shot log helpers ---------------

    def _prune_snapshot_dir(self):
        import pathlib
        p = pathlib.Path(self._snapshot_debug_dir)
        if not p.exists():
            return
        # newest first, delete the rest
        files = sorted(p.glob("snapshot_*.jpg"),
                    key=lambda f: f.stat().st_mtime,
                    reverse=True)
        for old in files[self._snapshot_keep:]:
            try:
                old.unlink()
                self.log.debug("Snapshot debug: pruned %s", old)
            except Exception as e:
                self.log.warning("Snapshot debug: failed to prune %s: %s", old, e)
    
    # -------------------- thread entry --------------------

    def run(self):
        current_key: Optional[Tuple[str, int, str]] = None

        while not self.stop_event.is_set():
            token = self.settings.get("mgmt.token")
            hostport = self.settings.get("mgmt.connectionHost")

            if not token or not hostport:
                self.log.debug("WSS: waiting for token/host...")
                self.token_event.wait(timeout=10)
                self.token_event.clear()
                continue

            host, port = _parse_hostport(str(hostport))
            key = (host, port, token)

            if key != current_key:
                self.log.info("WSS: (re)connecting to %s:%s (token/host changed)", host, port)
                current_key = key

            try:
                asyncio.run(self._connect_and_serve(host, port, token))
            except Exception as e:
                self.log.warning("WSS: connection failed: %s; retrying in 5s", e)
                self.token_event.wait(timeout=5)
                self.token_event.clear()

    # -------------------- async client --------------------

    async def _connect_and_serve(self, host: str, port: int, token: str):
        url = f"wss://{host}:{port}/camera/1.0/ws?token={token}"

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        # optional client certs if present
        if os.path.exists("cert.pem") and os.path.exists("key.pem"):
            try:
                ssl_ctx.load_cert_chain("cert.pem", "key.pem")
            except Exception as e:
                self.log.warning("WSS: could not load client cert/key: %s", e)

        headers = {
            "Camera-Mac": (self.settings.get("mac") or "").lower(),
            # your working code used hex sysid in Camera-Model
            "Camera-Model": self.settings.get("sysid") or "0xa573",
        }

        kwargs = dict(ssl=ssl_ctx, additional_headers=headers)
        if self.USE_SECURE_TRANSFER_SUBPROTOCOL:
            kwargs["subprotocols"] = ["secure_transfer"]

        self.log.info("WSS: connecting to controller")
        self.log.debug("WSS: URL=%s subprotocols=%s headers=%s", url, kwargs.get("subprotocols"), headers)

        async with websockets.connect(url, **kwargs) as ws:
            self.log.info("WSS: connected (agreed subprotocol=%s)", ws.subprotocol)
            try:
                self.log.debug("WSS: response headers: %s", dict(ws.response_headers))
            except Exception:
                pass
            await self._serve_loop(ws)

    async def _serve_loop(self, ws: WebSocketClientProtocol):
        # 1) send hello
        await self._send_hello(ws)

        # 2) read & dispatch
        try:
            async for incoming in ws:
                # Keep an untouched copy only for logging if JSON fails
                raw = incoming

                # If binary, try to decode; otherwise log & skip
                if isinstance(incoming, (bytes, bytearray)):
                    try:
                        incoming = incoming.decode("utf-8")
                    except Exception:
                        self._log_rx("", f"(binary {len(raw)} bytes)")
                        continue

                # Parse JSON first
                try:
                    msg = json.loads(incoming)
                except Exception:
                    preview = f"(non-JSON, {len(raw)} bytes)" if isinstance(raw, (bytes, bytearray)) else (raw[:500])
                    self._log_rx("", preview)
                    continue

                # Now we can safely read fields and do filtered logging
                fn   = msg.get("functionName", "")
                mid  = msg.get("messageId", 0)
                need = bool(msg.get("responseExpected"))
                self._log_rx(fn, incoming)

                if fn == "ubnt_avclient_hello":
                    self.log.debug("WSS: controller hello received (msgId=%s)", mid)
                    continue

                handler = self.handlers.get(fn)
                if handler:
                    await handler(ws, msg, need)
                else:
                    # Safety ACK if needed
                    if fn == "ubnt_avclient_paramAgreement" and need:
                        await self._reply(ws, msg, {"statusCode": 0, "status": "ok"})
                        continue
                    self.log.debug("WSS: unhandled %s (expect=%s): %s", fn, need, msg)

        except websockets.exceptions.ConnectionClosed as e:
            self.log.warning("WSS: server closed: code=%s reason=%s",
                            getattr(e, "code", None), getattr(e, "reason", None))
            raise
        except Exception:
            self.log.exception("WSS: serve_loop crashed")
            raise

    # -------------------- hello --------------------

    def _next_msg_id(self) -> int:
        self._msg_id += 1
        return self._msg_id
    
    async def _reply(self, ws: WebSocketClientProtocol, in_msg: dict, payload: dict):
        out = {
            "from": "ubnt_avclient",
            "to": "UniFiVideo",
            "functionName": in_msg.get("functionName"),
            "messageId": self._next_msg_id(),
            "inResponseTo": in_msg.get("messageId", 0),
            "payload": payload,
        }
        s = json.dumps(out, separators=(",", ":"))
        self._log_tx(out["functionName"], s)
        await ws.send(s)

    async def _reply_ok(self, ws: WebSocketClientProtocol, in_msg: dict, extra: dict | None = None):
        payload = {"status": "ok"}
        if extra:
            payload.update(extra)  # e.g., {"authToken": "..."} if you ever need it
        await self._reply(ws, in_msg, payload)

    async def _send_hello(self, ws: WebSocketClientProtocol):
        cam_ip = self.settings.get("host")  # camera's IP you expose
        hello = {
            "functionName": "ubnt_avclient_hello",
            "messageId": self._next_msg_id(),
            "payload": {
                "fwVersion": self.settings.get("firmwareVersion", "v5.0.129"),
                "ip": cam_ip,
                "uptime": int(self.settings.get("uptime", 0) or 0),
                "connectionHost": cam_ip,          # keep same as your working flow
                "connectionSecurePort": 7442,
                "protocolVersion": 1,
            },
        }
        s = json.dumps(hello, separators=(",", ":"))
        self._log_tx("ubnt_avclient_hello", s)
        await ws.send(s)

    async def _on_param_agreement(self, ws, msg, expect):
        if expect:
            await self._reply(ws, msg, {"statusCode": 0, "status": "ok"})

    async def _on_get_system_stats(self, ws: WebSocketClientProtocol, msg: dict, expect: bool):
        if expect:
            await self._reply(ws, msg, {
                "cpu": 5,
                "memory": 20,
                "temperature": 45,
                "uptime": int(self.settings.get("uptime", 0) or 0)
            })

    async def _on_network_status(self, ws: WebSocketClientProtocol, msg: dict, expect: bool):
        if expect:
            await self._reply(ws, msg, {
                "status": "connected",
                "ip": self.settings.get("host"),
                "mac": (self.settings.get("mac") or "").lower(),
            })

    def _device_id(self) -> str:
        return (self.settings.get("mac") or "").upper()

    async def _on_change_osd_settings(self, ws, msg, expect: bool):
        if expect:
            # Echo entire payload back
            incoming = msg.get("payload") or {}
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_change_sound_led_settings(self, ws, msg, expect: bool):
        if expect:
            incoming = msg.get("payload") or {}
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_change_talkback_settings(self, ws, msg, expect: bool):
        if expect:
            incoming = msg.get("payload") or {}
            # You can start your UDP/AAC server here later.
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_change_analytics_settings(self, ws, msg, expect: bool):
        if expect:
            incoming = msg.get("payload") or {}
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_change_device_settings(self, ws, msg, expect: bool):
        if expect:
            incoming = msg.get("payload") or {}
            # e.g. name/timezone/analyticsMode — echo back is fine
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_change_clarity_zones(self, ws, msg, expect: bool):
        if expect:
            incoming = msg.get("payload") or {}
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_update_face_db_request(self, ws, msg, expect: bool):
        if expect:
            payload = msg.get("payload") or {}
            await self._reply(ws, msg, {
                "statusCode": 0,
                "status": "ok",
                "deviceID": self._device_id(),
                **payload,
            })

    async def _on_update_username_password(self, ws, msg, expect: bool):
        if expect:
            # Stub OK (you can actually apply OS creds later)
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id()
            })

    async def _on_analytics_test(self, ws, msg, expect: bool):
        if expect:
            incoming = msg.get("payload") or {}
            await self._reply(ws, msg, {
                "statusCode": 0, "status": "ok", "deviceID": self._device_id(), **incoming
            })

    async def _on_get_request(self, ws, msg, expect: bool):
        payload = msg.get("payload") or {}
        if payload.get("what") != "snapshot":
            if expect:
                await self._reply(ws, msg, {"statusCode": 0, "status": "ok", "deviceID": self._device_id()})
            return

        uri = payload.get("uri")
        timeout_ms = int(payload.get("timeoutMs", 60000))
        timeout_s = max(1, timeout_ms // 1000)

        try:
            # Give the driver ~half the time to fetch the JPEG
            driver_timeout = max(1, timeout_s // 2)
            jpeg = await self.driver.get_snapshot_jpeg(timeout_s=driver_timeout)

            # DEBUG: write a copy locally if SNAPSHOT_DEBUG_DIR is set
            debug_dir = os.getenv("SNAPSHOT_DEBUG_DIR")
            if self._snapshot_debug:
                try:
                    import hashlib, time as _time, pathlib
                    sha = hashlib.sha256(jpeg).hexdigest()
                    head = jpeg[:8].hex()

                    # log some quick visibility
                    self.log.info(
                        "Snapshot debug: len=%d sha256=%s… head=%s",
                        len(jpeg), sha[:12], head
                    )

                    # write file to static dir and prune to last N
                    p = pathlib.Path(self._snapshot_debug_dir)
                    p.mkdir(parents=True, exist_ok=True)
                    out = p / f"snapshot_{int(_time.time())}.jpg"
                    out.write_bytes(jpeg)
                    self._prune_snapshot_dir()
                    self.log.info("Saved snapshot for debug: %s (%d bytes)", out, len(jpeg))

                except Exception as _e:
                    self.log.warning("Snapshot debug failed: %s", _e)

            await self._upload_snapshot_and_ack(ws, msg, jpeg, uri, timeout_s)
        except Exception as e:
            self.log.error("get_snapshot_jpeg failed: %s", e)
            if expect:
                await self._reply(ws, msg, {"statusCode": 1, "status": "error", "deviceID": self._device_id()})

    async def _on_change_video_settings(self, ws, msg, expect: bool):
        if not expect: return
        payload = msg.get("payload") or {}
        applied = await self.driver.apply_video_settings(payload)
        out = {"statusCode": 0, "status": "ok", "deviceID": self._device_id()}
        out.update(applied)  # controller may read back “video” etc.
        await self._reply(ws, msg, out)

    async def _on_change_isp_settings(self, ws, msg, expect: bool):
        if not expect: return
        payload = msg.get("payload") or {}
        applied = await self.driver.apply_isp_settings(payload)
        out = {"statusCode": 0, "status": "ok", "deviceID": self._device_id()}
        out.update(applied)
        await self._reply(ws, msg, out)

    async def _on_time_sync(self, ws: WebSocketClientProtocol, msg: dict, expect: bool):
        # Controller expects camera to echo current time in ms
        now_ms = int(time.time() * 1000)
        # Most firmwares reply with { t1, t2 }; either is fine for basic sync
        await self._reply(ws, msg, {"t1": now_ms, "t2": now_ms})

    async def _upload_snapshot_and_ack(self, ws: WebSocketClientProtocol, in_msg: dict, jpeg_bytes: bytes, uri: str, timeout_s: int):
        """
        PUT raw JPEG to the controller-provided HTTPS URI, then reply OK/ERROR.
        """
        from urllib import request as _u, error as _e
        import ssl as _ssl

        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        req = _u.Request(uri, data=jpeg_bytes, method="PUT")
        req.add_header("Content-Type", "image/jpeg")
        req.add_header("Content-Length", str(len(jpeg_bytes)))

        try:
            opener = _u.build_opener(_u.HTTPSHandler(context=ctx))
            resp = await asyncio.to_thread(opener.open, req, timeout=timeout_s)
            code = getattr(resp, "code", None)
            self.log.debug("Snapshot upload HTTP status=%s (len=%d)", code, len(jpeg_bytes))

            if code in (200, 204):
                await self._reply(ws, in_msg, {"statusCode": 0, "status": "ok", "deviceID": self._device_id()})
            else:
                self.log.error("Snapshot upload unexpected status=%s", code)
                await self._reply(ws, in_msg, {"statusCode": 1, "status": "error", "deviceID": self._device_id()})
        except _e.URLError as e:
            self.log.error("Snapshot upload failed: %s", e)
            await self._reply(ws, in_msg, {"statusCode": 1, "status": "error", "deviceID": self._device_id()})
        except Exception as e:
            self.log.error("Snapshot upload exception: %s", e)
            await self._reply(ws, in_msg, {"statusCode": 1, "status": "error", "deviceID": self._device_id()})
