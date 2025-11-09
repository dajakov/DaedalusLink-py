import json
import time
import threading
import asyncio
import socket
from websocket_server import WebsocketServer


class DaedalusLink:
    def __init__(self, name, link_id):
        self.name = name
        self.link_id = link_id
        self.server = None
        self.interface_data = []
        self.callbacks = {}
        self.clients = []
        self.client_last_seen = {}
        self.broadcast_config = None
        self.broadcast_thread = None
        self._broadcast_stop_event = threading.Event()

    # --- GUI Elements ---
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

    # --- Event Handling ---
    def on(self, command):
        def decorator(fn):
            self.callbacks[command] = fn
            return fn
        return decorator

    # --- Server Handling ---
    def _send_config(self, client):
        config = {
            "type": "config",
            "payload": {
                "linkId": self.link_id,
                "name": self.name,
                "commandUpdateFrequency": 500,
                "sensorUpdateFrequency": 1000,
                "debugLogUpdateFrequency": 2000,
                "interfaceData": self.interface_data
            }
        }
        self.server.send_message(client, json.dumps(config))

    def _on_new_client(self, client, server):
        self.clients.append(client)
        print(f"New client connected: {client['id']}")
        self._send_config(client)

    def _on_client_left(self, client, server):
        print(f"Client {client['id']} disconnected")

        cid = client["id"]
        if cid in self.client_last_seen:
            del self.client_last_seen[cid]

        if client in self.clients:
            self.clients.remove(client)

    def _on_message(self, client, server, message):
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            # Handle raw text: e.g. "move 108,-75" or "slider 42"
            parts = message.split(" ", 1)
            cmd = parts[0]
            payload = parts[1] if len(parts) > 1 else None
            msg = {"command": cmd, "data": payload}

        cmd = msg.get("command") or msg.get("type") or msg.get("payload")
        if not cmd:
            return

        # client heartbeat
        if cmd == "ack":
            client_id = client["id"]
            self.client_last_seen[client_id] = time.time()

            # Echo back heartbeat ack
            hb_ack = {
                "type": "ack",
                "command": "heartbeat",
                "timestamp": int(time.time())
            }
            self.server.send_message(client, json.dumps(hb_ack))
            return

        # Handle button press/release
        pressed = True
        if isinstance(cmd, str) and cmd.startswith("!"):
            cmd = cmd[1:]
            pressed = False

        args = []
        data = msg.get("data")

        if cmd in self.callbacks:
            fn = self.callbacks[cmd]

            # Parse payload into args
            if data is None:
                args = [pressed]
                fn(*args)
            elif isinstance(data, str):
                if "," in data:
                    args = [arg.strip() for arg in data.split(",")]
                    args = [int(a) if a.lstrip("-").isdigit() else a for a in args]
                    fn(*args)
                elif data.lstrip("-").isdigit():
                    args = [int(data)]
                    fn(*args)
                else:
                    args = [data]
                    fn(*args)
            elif isinstance(data, list):
                args = data
                fn(*args)
            else:
                args = [data]
                fn(*args)

            # Send structured command ack
            ack = {
                "type": "ack",
                "command": cmd,
                "args": args,
                "timestamp": int(time.time())
            }
            self.server.send_message(client, json.dumps(ack))

        else:
            # Unknown command → send error
            error_msg = {
                "type": "error",
                "error": f"Unknown command: {cmd}",
                "timestamp": int(time.time())
            }
            self.server.send_message(client, json.dumps(error_msg))

    def enable_discovery_broadcast(
        self,
        udp_port: int = 7777,
        interval: float = 1.0,
    ):
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

    def run(self, port=8081, debug=True):
        self.server = WebsocketServer(host="0.0.0.0", port=port)
        self.server.set_fn_new_client(self._on_new_client)
        self.server.set_fn_message_received(self._on_message)
        self.server.set_fn_client_left(self._on_client_left)

        print(f"[DaedalusLink] WebSocket running at ws://0.0.0.0:{port}")

        if self.broadcast_config:
            self._start_broadcast_thread()

        try:
            self.server.run_forever()
        except KeyboardInterrupt:
            print("\n[DaedalusLink] Stopping server...")
        finally:
            self.disable_discovery_broadcast()
