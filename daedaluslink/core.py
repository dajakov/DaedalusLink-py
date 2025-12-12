# daedaluslink_v2.py
import os
import hmac
import hashlib
import random
import string
import json
import time
import threading
import asyncio
import socket
from websocket_server import WebsocketServer


class DaedalusLink:
    """
    DaedalusLink v2
    - Protocol "checking in on ya" (proto_major/proto_minor) sent on connect
    - Optional challenge-response HMAC auth
    - Per-connection metadata (authenticated, username, role, device_id)
    - Role-based command enforcement
    - Discovery broadcast (UDP)
    """

    def __init__(self, name, link_id):
        # identity
        self.name = name
        self.link_id = link_id

        # websocket server
        self.server = None

        # GUI description
        self.interface_data = []
        self.callbacks = {}
        self.command_roles = {}  # command -> list of allowed roles (None = any)

        # connection bookkeeping
        self.clients = []
        self.client_meta = {}  # client_id -> dict with metadata
        self.client_last_seen = {}

        # discovery broadcast
        self.broadcast_config = None
        self.broadcast_thread = None
        self._broadcast_stop_event = threading.Event()

        # authentication
        self.auth_enabled = False
        # users: username -> {"password": "plain_or_hash", "role": "..."}
        # NOTE: for production consider storing hashed passwords and verifying with bcrypt.
        self.users = {}
        # pending challenges: client_id -> challenge
        self.pending_challenges = {}
        # authenticated mapping: client_id -> username/role stored in client_meta
        # (we keep client_meta for all per-client state)

        # protocol version
        self.proto_major = 1
        self.proto_minor = 0

    # -------------------------
    # Public APIs
    # -------------------------
    def set_protocol_version(self, major: int, minor: int):
        """Set server protocol version sent to clients on connect."""
        self.proto_major = int(major)
        self.proto_minor = int(minor)

    def enable_authentication(self):
        """Require challenge-response HMAC auth before sending config/accepting commands."""
        self.auth_enabled = True

    def disable_authentication(self):
        self.auth_enabled = False

    def add_user(self, username: str, password: str, role: str = "user"):
        """
        Add a user. For MCU-style deployments you may keep plaintext; in normal servers
        you should store salted hashes and verify accordingly.
        """
        self.users[str(username)] = {"password": str(password), "role": str(role)}

    def remove_user(self, username: str):
        if username in self.users:
            del self.users[username]

    def set_command_roles(self, command: str, roles: list):
        """
        Restrict a command to certain roles, e.g. ["admin", "developer"].
        Pass roles=None to allow all authenticated users.
        """
        self.command_roles[command] = None if roles is None else list(roles)

    def add_button(self, label, command=None, position=[0, 0], size=[2, 1]):
        self.interface_data.append({
            "type": "button",
            "label": label,
            "position": position,
            "size": size,
            "command": command
        })

    def add_slider(self, label, command=None, position=[0, 0], size=[1, 5]):
        self.interface_data.append({
            "type": "slider",
            "label": label,
            "position": position,
            "size": size,
            "command": command
        })

    def add_joystick(self, label, axes=["X", "Y"], command=None, position=[0, 0], size=[4, 4]):
        self.interface_data.append({
            "type": "joystick",
            "label": label,
            "position": position,
            "size": size,
            "axes": axes,
            "command": command
        })

    def on(self, command):
        def decorator(fn):
            self.callbacks[command] = fn
            return fn
        return decorator

    # -------------------------
    # Internal helpers
    # -------------------------
    def _send_hello(self, client):
        """Send initial hello message including protocol version and whether auth is required."""
        checking_in_on_ya = {
            "type": "checking_in_on_ya",
            "proto_major": self.proto_major,
            "proto_minor": self.proto_minor,
            "auth_required": bool(self.auth_enabled),
            "linkId": self.link_id,
            "name": self.name,
        }
        self.server.send_message(client, json.dumps(checking_in_on_ya))

    def _send_config(self, client):
        """Send GUI config payload (only after auth if enabled)."""
        # Optionally tailor config by role
        cid = client["id"]
        meta = self.client_meta.get(cid, {})

        interface = list(self.interface_data)
        # Example: append debug control for developers/admins

        config = {
            "type": "config",
            "payload": {
                "linkId": self.link_id,
                "name": self.name,
                "commandUpdateFrequency": 500,
                "sensorUpdateFrequency": 1000,
                "debugLogUpdateFrequency": 2000,
                "interfaceData": interface,
            }
        }
        self.server.send_message(client, json.dumps(config))

    def _generate_challenge(self, length=32):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _cleanup_client(self, client):
        cid = client["id"]
        # remove challenge if any
        if cid in self.pending_challenges:
            del self.pending_challenges[cid]
        if cid in self.client_meta:
            del self.client_meta[cid]
        if cid in self.client_last_seen:
            del self.client_last_seen[cid]
        # remove from clients list if present
        try:
            if client in self.clients:
                self.clients.remove(client)
        except Exception:
            # sometimes client equality is not direct; remove by id
            self.clients = [c for c in self.clients if c.get("id") != cid]

    def _verify_signed_packet(self, cid, msg):
        """
        Verify the HMAC signature, timestamp and nonce for replay protection.
        Requires client to be authenticated.
        """

        meta = self.client_meta.get(cid)
        if not meta or not meta.get("authenticated"):
            return False, "not authenticated"

        username = meta["username"]
        user = self.users.get(username)
        if not user:
            return False, "unknown user"

        password = user["password"]              # (plaintext or hash-for-MCU)

        ts = msg.get("ts")
        nonce = msg.get("nonce")
        signature = msg.get("signature")

        if ts is None or nonce is None or signature is None:
            return False, "missing ts/nonce/signature"

        # 1) timestamp freshness (±10 seconds)
        now = int(time.time())
        if abs(now - int(ts)) > 10:
            return False, "timestamp expired"

        # 2) nonce uniqueness
        nonce_map = self.used_nonces.setdefault(cid, {})
        if nonce in nonce_map:
            return False, "nonce replay detected"
        # store nonce with timestamp
        nonce_map[nonce] = now

        # cleanup old nonces (>10s)
        for n, t in list(nonce_map.items()):
            if now - t > 10:
                del nonce_map[n]

        # 3) verify HMAC signature
        content = json.dumps({
            "ts": ts,
            "nonce": nonce,
            "command": msg.get("command"),
            "data": msg.get("data")
        }, separators=(",", ":"), sort_keys=True)

        expected = hmac.new(
            password.encode(),
            content.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            return False, "invalid signature"

        return True, ""

    def _is_command_allowed_for_client(self, client, command):
        """Role-based command enforcement. Returns (allowed: bool, reason:str)."""
        cid = client["id"]
        meta = self.client_meta.get(cid, {})
        if self.auth_enabled and not meta.get("authenticated"):
            return False, "Not authenticated"

        required_roles = self.command_roles.get(command, None)
        if required_roles is None:
            # no role restriction
            return True, ""
        role = meta.get("role")
        if role in required_roles:
            return True, ""
        return False, f"forbidden: role '{role}' not allowed"

    # -------------------------
    # Websocket event handlers
    # -------------------------
    def _on_new_client(self, client, server):
        cid = client["id"]
        print(f"[DaedalusLink] New client connected: {cid}")

        # store client in list and init meta
        self.clients.append(client)
        self.client_meta[cid] = {
            "authenticated": False,
            "username": None,
            "role": None,
            "connected_at": int(time.time()),
            "device_id": None
        }

        # Always send hello first so clients can version-negotiate or react to auth_required
        self._send_hello(client)

        # If auth disabled: send config immediately
        if not self.auth_enabled:
            self._send_config(client)
            return

        # If auth enabled: generate challenge and send explicit auth_required (client may already expect it)
        challenge = self._generate_challenge()
        self.pending_challenges[cid] = challenge

        auth_msg = {
            "type": "auth_required",
            "challenge": challenge,
            "roles": ["user", "developer", "admin"]
        }
        self.server.send_message(client, json.dumps(auth_msg))

    def _on_client_left(self, client, server):
        print(f"[DaedalusLink] Client {client['id']} disconnected")
        # cleanup state
        self._cleanup_client(client)

    def _on_message(self, client, server, message):
        cid = client["id"]
        # try parse JSON first
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            # Backwards-compatible: raw text handling as before
            parts = message.split(" ", 1)
            cmd = parts[0]
            payload = parts[1] if len(parts) > 1 else None
            msg = {"command": cmd, "data": payload}

        # Determine command/type field
        cmd = msg.get("command") or msg.get("type") or msg.get("payload")
        if not cmd:
            return

        # Handle checking in protocol from client (optional): client may send its own proto info
        if cmd == "checking_in_on_ya":
            client_proto_maj = int(msg.get("proto_major", 0))
            client_proto_min = int(msg.get("proto_minor", 0))
            device_id = msg.get("device_id")
            # store device_id if provided
            if device_id:
                self.client_meta[cid]["device_id"] = device_id

            # Basic compatibility check: server rejects if client major != server major
            if client_proto_maj != self.proto_major:
                # send incompatible notice and close
                incompat = {
                    "type": "incompatible",
                    "message": "protocol_major_mismatch",
                    "server_proto_major": self.proto_major,
                    "server_proto_minor": self.proto_minor,
                    "client_proto_major": client_proto_maj,
                    "client_proto_minor": client_proto_min
                }
                self.server.send_message(client, json.dumps(incompat))
                try:
                    server.close_client(client)
                except Exception:
                    pass
                return
            # otherwise accept and keep going (client will still need to auth if required)
            # ack hello
            self.server.send_message(client, json.dumps({
                "type": "checking_in_on_ya_ack",
                "proto_major": self.proto_major,
                "proto_minor": self.proto_minor
            }))
            return

        # Authentication flow
        if cmd == "auth":
            username = msg.get("username")
            response = msg.get("response")
            challenge = self.pending_challenges.get(cid)

            if not username or not response or not challenge:
                self.server.send_message(client, json.dumps({
                    "type": "auth_error",
                    "message": "Invalid auth request"
                }))
                return

            user = self.users.get(username)
            if not user:
                self.server.send_message(client, json.dumps({
                    "type": "auth_error",
                    "message": "User not found"
                }))
                return

            # compute expected HMAC: HMAC_SHA256(key=password, message=challenge)
            expected = hmac.new(
                user["password"].encode(),
                challenge.encode(),
                hashlib.sha256
            ).hexdigest()

            if hmac.compare_digest(response, expected):
                # authenticated
                self.client_meta[cid].update({
                    "authenticated": True,
                    "username": username,
                    "role": user.get("role", "user"),
                    "auth_time": int(time.time())
                })
                # clear pending challenge
                if cid in self.pending_challenges:
                    del self.pending_challenges[cid]

                print(f"[DaedalusLink] Client {cid} authenticated as {username} ({user.get('role')})")

                # send success + role info
                self.server.send_message(client, json.dumps({
                    "type": "auth_success",
                    "role": user.get("role", "user")
                }))

                # send config now that client is authenticated
                self._send_config(client)
            else:
                # invalid signature
                self.server.send_message(client, json.dumps({
                    "type": "auth_error",
                    "message": "Invalid signature"
                }))
            return

        # heartbeat / ack handling
        if cmd == "ack":
            self.client_last_seen[cid] = time.time()
            hb_ack = {
                "type": "ack",
                "command": "heartbeat",
                "timestamp": int(time.time())
            }
            self.server.send_message(client, json.dumps(hb_ack))
            return

        # If auth is enabled and client not authenticated, refuse any non-auth commands
        if self.auth_enabled and not self.client_meta.get(cid, {}).get("authenticated", False):
            self.server.send_message(client, json.dumps({
                "type": "error",
                "message": "Not authenticated"
            }))
            return

        # If auth enabled, all commands must be signed (except 'auth' itself)
        if self.auth_enabled:
            ok, reason = self._verify_signed_packet(cid, msg)
            if not ok:
                self.server.send_message(client, json.dumps({
                    "type": "error",
                    "message": f"security: {reason}"
                }))
                return

        # From this point, the client is allowed to issue commands (or auth disabled)
        # Figure out pressed state (legacy behavior) and data payload
        pressed = True
        if isinstance(cmd, str) and cmd.startswith("!"):
            cmd = cmd[1:]
            pressed = False

        data = msg.get("data")

        # enforce role restrictions if configured
        allowed, reason = self._is_command_allowed_for_client(client, cmd)
        if not allowed:
            self.server.send_message(client, json.dumps({
                "type": "error",
                "message": reason
            }))
            return

        # dispatch to callback if present
        if cmd in self.callbacks:
            fn = self.callbacks[cmd]
            args = []
            try:
                if data is None:
                    # no explicit data → use pressed boolean (legacy)
                    args = [pressed]
                    fn(*args)
                elif isinstance(data, str):
                    # string may be comma-separated or single int or text
                    if "," in data:
                        parts = [p.strip() for p in data.split(",")]
                        # convert numeric parts to int when possible
                        parsed = [int(p) if p.lstrip("-").isdigit() else p for p in parts]
                        fn(*parsed)
                    elif data.lstrip("-").isdigit():
                        fn(int(data))
                    else:
                        fn(data)
                elif isinstance(data, list):
                    # pass list elements as positional args
                    fn(*data)
                else:
                    # other types passed as single argument
                    fn(data)
            except Exception as e:
                # notify client about handler error but do not crash
                self.server.send_message(client, json.dumps({
                    "type": "error",
                    "message": f"handler error: {e}"
                }))
                return

            # ack the command
            ack = {
                "type": "ack",
                "command": cmd,
                "args": args,
                "timestamp": int(time.time())
            }
            self.server.send_message(client, json.dumps(ack))
        else:
            # unknown command
            self.server.send_message(client, json.dumps({
                "type": "error",
                "error": f"Unknown command: {cmd}",
                "timestamp": int(time.time())
            }))

    # -------------------------
    # Discovery broadcast
    # -------------------------
    def enable_discovery_broadcast(self, udp_port: int = 7777, interval: float = 1.0):
        """Configure UDP discovery broadcast (starts automatically on run())."""
        self.broadcast_config = {
            "robotId": self.link_id,
            "name": self.name,
            "wsPort": 8081,
            "udpPort": udp_port,
            "interval": interval,
        }

    def disable_discovery_broadcast(self):
        """Stop discovery broadcasting."""
        if self.broadcast_thread and self.broadcast_thread.is_alive():
            print("[DaedalusLink] Stopping discovery broadcast...")
            self._broadcast_stop_event.set()
            self.broadcast_thread.join(timeout=2)
        self.broadcast_config = None
        self.broadcast_thread = None
        self._broadcast_stop_event.clear()
        print("[DaedalusLink] Discovery broadcast disabled.")

    async def _broadcast_loop(self):
        """Internal async loop for broadcasting."""
        cfg = self.broadcast_config
        if not cfg:
            return

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.setblocking(False)

        msg = json.dumps({
            "robotId": cfg["robotId"],
            "name": cfg["name"],
            "wsPort": cfg["wsPort"],
            "proto_major": self.proto_major,
            "proto_minor": self.proto_minor,
            "auth_required": bool(self.auth_enabled)
        }).encode("utf-8")

        while not self._broadcast_stop_event.is_set():
            try:
                udp_socket.sendto(msg, ("255.255.255.255", cfg["udpPort"]))
            except Exception as e:
                print(f"[DaedalusLink] UDP broadcast error: {e}")
            await asyncio.sleep(cfg["interval"])

        udp_socket.close()

    def _start_broadcast_thread(self):
        """Start background thread for broadcasting (only if configured)."""
        if not self.broadcast_config:
            return
        if self.broadcast_thread and self.broadcast_thread.is_alive():
            return

        self._broadcast_stop_event.clear()
        self.broadcast_thread = threading.Thread(
            target=lambda: asyncio.run(self._broadcast_loop()),
            daemon=True
        )
        self.broadcast_thread.start()
        print("[DaedalusLink] Discovery broadcast started.")

    # -------------------------
    # Run server
    # -------------------------
    def run(self, port=8081, debug=True):
        self.server = WebsocketServer(host="0.0.0.0", port=port)
        self.server.set_fn_new_client(self._on_new_client)
        self.server.set_fn_message_received(self._on_message)
        self.server.set_fn_client_left(self._on_client_left)

        print(f"[DaedalusLink] WebSocket running at ws://0.0.0.0:{port} (proto {self.proto_major}.{self.proto_minor})")

        if self.broadcast_config:
            self._start_broadcast_thread()

        try:
            self.server.run_forever()
        except KeyboardInterrupt:
            print("\n[DaedalusLink] Stopping server...")
        finally:
            self.disable_discovery_broadcast()
