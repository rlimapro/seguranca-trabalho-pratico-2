"""Local web control panel for the TP3 E2E messaging protocol."""

from __future__ import annotations

import asyncio
import argparse
import errno
import json
import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from client.client import (
    AdminClientConnection,
    ClientHandshake,
    apply_peer_event,
    establish_admin_channel,
    perform_client_handshake,
)
from common.admin import ADMIN_TYPES
from common.e2e import (
    E2EAuthenticationError,
    E2EProtocolError,
    E2EReplayError,
    receive_e2e,
    send_e2e,
)
from common.framing import FrameError, recv_frame
from common.protocol import E2E, ERROR, PEER_INFO, PEER_LEFT
from server.handshake_server import ConnectionLimiter, handle_handshake_client

WEB_ROOT = Path(__file__).resolve().parent
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("tp3.web")


def create_lab_certificate() -> tuple[bytes, rsa.RSAPrivateKey]:
    """Create an in-memory demo identity; the private key is never written out."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "tp3-local-lab")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER), key


class Lab:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.guard = threading.RLock()
        self.transition_lock = asyncio.Lock()
        self.thread = threading.Thread(target=self._run_loop, name="tp3-lab-loop", daemon=True)
        self.thread.start()
        self.running_server: asyncio.AbstractServer | None = None
        self.certificate_der: bytes | None = None
        self.signing_key: rsa.RSAPrivateKey | None = None
        self.sessions: dict[bytes, dict] = {}
        self.sessions_lock: asyncio.Lock | None = None
        self.limiter: ConnectionLimiter | None = None
        self.clients: dict[bytes, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.messages: list[dict[str, Any]] = []
        self.started_at: str | None = None

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def call(self, coro, timeout: float = 8.0):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout)

    def emit(
        self,
        kind: str,
        title: str,
        detail: str,
        *,
        actor: str = "system",
        client_id: bytes | None = None,
        peer_id: bytes | None = None,
        severity: str = "info",
    ) -> None:
        event = {
            "id": uuid.uuid4().hex,
            "time": datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3],
            "kind": kind,
            "title": title,
            "detail": detail,
            "actor": actor,
            "client_id": client_id.hex() if client_id else None,
            "peer_id": peer_id.hex() if peer_id else None,
            "severity": severity,
        }
        with self.guard:
            self.events.append(event)
            self.events = self.events[-300:]

    async def start_server(self) -> dict[str, Any]:
        async with self.transition_lock:
            return await self._start_server()

    async def _start_server(self) -> dict[str, Any]:
        if self.running_server is not None:
            return {"running": True, "message": "Servidor já está ativo."}
        self.certificate_der, self.signing_key = create_lab_certificate()
        self.sessions = {}
        self.sessions_lock = asyncio.Lock()
        self.limiter = ConnectionLimiter(32)
        with self.guard:
            self.clients.clear()
            self.events.clear()
            self.messages.clear()

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            return handle_handshake_client(
                reader,
                writer,
                self.signing_key,
                self.certificate_der,
                self.sessions,
                self.sessions_lock,
                self.limiter,
            )

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        with self.guard:
            self.running_server = server
        address = server.sockets[0].getsockname()
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.emit(
            "server",
            "Servidor iniciado",
            f"Relay ouvindo em 127.0.0.1:{address[1]}; certificado RSA-PSS criado em memória.",
        )
        return {"running": True, "port": address[1]}

    async def stop_server(self) -> dict[str, Any]:
        async with self.transition_lock:
            return await self._stop_server()

    async def _stop_server(self) -> dict[str, Any]:
        if self.running_server is None:
            return {"running": False, "message": "Servidor já está parado."}
        server = self.running_server
        server.close()
        # Publish the stopped state before awaiting socket teardown. Polling
        # requests can then never index the listener's emptied socket tuple.
        with self.guard:
            self.running_server = None
        await server.wait_closed()
        for state in tuple(self.clients.values()):
            state["handshake"].writer.close()
        tasks = [state["receiver"] for state in tuple(self.clients.values())]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        with self.guard:
            self.clients.clear()
        self.emit("server", "Servidor encerrado", "Todas as sessões locais foram fechadas.")
        return {"running": False}

    async def create_client(self, label: str) -> dict[str, Any]:
        if self.running_server is None or self.certificate_der is None:
            raise ValueError("Inicie o servidor antes de criar clientes.")
        label = " ".join(label.split())[:28] or f"Cliente {len(self.clients) + 1}"
        # Resolve the ephemeral listener port and create a real protocol client.
        port = self.running_server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            self.emit("handshake", f"{label}: chave efêmera X25519", "O cliente gera sk_C localmente e prepara pk_C raw de 32 bytes.", actor=label)
            handshake = await perform_client_handshake(reader, writer, self.certificate_der)
            self.emit("handshake", f"{label}: HELLO enviado", "client_id (16 B) e pk_C (32 B) seguem no primeiro frame.", actor=label, client_id=handshake.client_id)
            self.emit("handshake", "Servidor prova sua identidade", "Gera pk_S efêmera e salt; assina o transcript com RSA-PSS/SHA-256.", actor="Servidor", client_id=handshake.client_id)
            self.emit("handshake", f"{label}: SERVER_HELLO validado", "Certificado pinado confere e a assinatura autentica pk_S, pk_C, ID e salt.", actor=label, client_id=handshake.client_id)
            admin = await establish_admin_channel(handshake)
            state = {
                "id": handshake.client_id,
                "label": label,
                "handshake": handshake,
                "admin": admin,
                "peers": admin.peers,
                "known_peers": admin.known_peers,
                "receiver": None,
            }
            with self.guard:
                self.clients[handshake.client_id] = state
            self.emit("admin", f"{label}: canal administrativo pronto", "ECDH cliente-servidor deriva chaves C2S/S2C; confirmação autenticada recebida.", actor=label, client_id=handshake.client_id)
            self.emit("session", "Sessão registrada", "sessions guarda ID, pk pública, salt, writer e contadores administrativos.", actor="Servidor", client_id=handshake.client_id)
            state["receiver"] = asyncio.create_task(self._receive(state))
            return self._client_summary(state)
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            raise

    async def _receive(self, state: dict[str, Any]) -> None:
        handshake: ClientHandshake = state["handshake"]
        admin: AdminClientConnection = state["admin"]
        try:
            while True:
                message_type, payload = await recv_frame(handshake.reader)
                if message_type in ADMIN_TYPES:
                    message_type, plaintext, _seq = admin.channel.decode_admin_frame(message_type, payload)
                    with self.guard:
                        result = apply_peer_event(
                            handshake,
                            admin.known_peers,
                            admin.peers,
                            message_type,
                            plaintext,
                        )
                    if message_type == PEER_INFO and result:
                        peer_id, peer_fp = result
                        peer_state = self.clients.get(peer_id)
                        peer_name = peer_state["label"] if peer_state else peer_id.hex()[:8]
                        self.emit(
                            "rendezvous",
                            f"{state['label']} recebeu PEER_INFO de {peer_name}",
                            f"pk e salt chegam cifrados no canal administrativo; fingerprint {peer_fp}.",
                            actor=state["label"],
                            client_id=handshake.client_id,
                            peer_id=peer_id,
                        )
                        self.emit(
                            "derive",
                            f"Chaves E2E prontas: {state['label']} ↔ {peer_name}",
                            "ECDH local + HKDF com salts ordenados por ID deriva A2B/B2A; Z é descartado.",
                            actor=state["label"],
                            client_id=handshake.client_id,
                            peer_id=peer_id,
                        )
                    elif message_type == PEER_LEFT:
                        peer_id = result[0] if result else None
                        self.emit("disconnect", f"Peer saiu de {state['label']}'s lista", "PEER_LEFT autenticado remove metadados e chaves locais.", actor=state["label"], client_id=handshake.client_id, peer_id=peer_id)
                    elif message_type == ERROR:
                        self.emit("admin", f"Aviso para {state['label']}", plaintext.decode("utf-8", errors="replace"), actor="Servidor", client_id=handshake.client_id)
                elif message_type == E2E:
                    try:
                        sender_id, plaintext = receive_e2e(handshake.client_id, admin.peers, payload)
                    except E2EReplayError:
                        self.emit("reject", "Replay rejeitado", "seq_no já aceito; o contador não retrocede.", actor=state["label"], client_id=handshake.client_id, severity="warning")
                    except E2EAuthenticationError:
                        self.emit("reject", "Tag GCM inválida", "Bitflip detectado; seq_recv não avança e a conexão continua.", actor=state["label"], client_id=handshake.client_id, severity="warning")
                    except E2EProtocolError as exc:
                        self.emit("reject", "Frame E2E rejeitado", str(exc), actor=state["label"], client_id=handshake.client_id, severity="warning")
                    else:
                        sender = self.clients.get(sender_id, {}).get("label", sender_id.hex()[:8])
                        message = plaintext.decode("utf-8", errors="replace")
                        with self.guard:
                            self.messages.append({"from": sender, "to": state["label"], "text": message})
                            self.messages = self.messages[-100:]
                        self.emit("message", f"Mensagem aberta por {state['label']}", f"De {sender}: {message}", actor=state["label"], client_id=handshake.client_id, peer_id=sender_id)
                else:
                    raise FrameError(f"unexpected frame type 0x{message_type:02x}")
        except (asyncio.IncompleteReadError, FrameError, ConnectionError, OSError):
            if self.running_server is not None:
                self.emit("disconnect", f"{state['label']} desconectado", "A conexão foi encerrada.", actor=state["label"], client_id=handshake.client_id, severity="muted")

    async def send_message(self, sender_hex: str, recipient_hex: str, text: str, attack: str | None):
        try:
            sender_id, recipient_id = bytes.fromhex(sender_hex), bytes.fromhex(recipient_hex)
        except ValueError as exc:
            raise ValueError("IDs inválidos.") from exc
        sender = self.clients.get(sender_id)
        recipient = self.clients.get(recipient_id)
        if sender is None or recipient is None:
            raise ValueError("Remetente ou destinatário não está conectado.")
        if recipient_id not in sender["peers"]:
            raise ValueError("O rendezvous ainda não concluiu para esse par.")
        payload = text.encode("utf-8")
        if not payload:
            raise ValueError("A mensagem não pode ser vazia.")
        await send_e2e(
            sender["handshake"].writer,
            sender_id,
            recipient_id,
            sender["peers"][recipient_id],
            payload,
            attack=attack,
        )
        if attack == "bitflip":
            title, detail, severity = "Bitflip aplicado", "Um bit da tag foi alterado; o relay não detecta o ataque.", "warning"
        elif attack == "replay":
            title, detail, severity = "Replay transmitido", "O mesmo frame E2E foi enviado duas vezes.", "warning"
        else:
            title, detail, severity = "Frame E2E encaminhado", "O servidor roteia pelo recipient_id e repassa bytes cifrados sem a chave E2E.", "info"
        self.emit("relay", title, detail, actor="Servidor", client_id=sender_id, peer_id=recipient_id, severity=severity)
        return {"sent": True}

    async def disconnect_client(self, client_hex: str) -> dict[str, Any]:
        try:
            client_id = bytes.fromhex(client_hex)
        except ValueError as exc:
            raise ValueError("ID de cliente inválido.") from exc
        state = self.clients.get(client_id)
        if state is None:
            raise ValueError("Cliente não encontrado.")
        state["handshake"].writer.close()
        receiver = state.get("receiver")
        if receiver is not None:
            await asyncio.gather(receiver, return_exceptions=True)
        with self.guard:
            self.clients.pop(client_id, None)
        self.emit("disconnect", f"{state['label']} saiu", "O servidor limpa a sessão e notifica os outros peers com PEER_LEFT.", actor="Servidor", client_id=client_id)
        return {"disconnected": True}

    async def send_invalid_framing(self) -> dict[str, Any]:
        if self.running_server is None:
            raise ValueError("Inicie o servidor primeiro.")
        port = self.running_server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write((0xFFFFFFFF).to_bytes(4, "big"))
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        self.emit("framing", "Tamanho de frame abusivo rejeitado", "MAX_FRAME impede a alocação; o servidor encerra apenas a conexão afetada.", actor="Servidor", severity="warning")
        return {"rejected": True}

    def _client_summary(self, state: dict[str, Any]) -> dict[str, Any]:
        handshake: ClientHandshake = state["handshake"]
        from common.crypto import fingerprint

        return {
            "id": handshake.client_id.hex(),
            "uuid": str(uuid.UUID(bytes=handshake.client_id)),
            "label": state["label"],
            "fingerprint": fingerprint(handshake.public_key),
            "peers": [peer.hex() for peer in state["known_peers"]],
        }

    def snapshot(self) -> dict[str, Any]:
        with self.guard:
            clients = [self._client_summary(state) for state in self.clients.values()]
            server = self.running_server
            sockets = server.sockets if server is not None else ()
            running = bool(sockets)
            port = sockets[0].getsockname()[1] if running else None
            return {
                "running": running,
                "port": port,
                "clients": clients,
                "events": list(self.events),
                "messages": list(self.messages),
                "max_clients": 32,
            }


LAB = Lab()


class Handler(BaseHTTPRequestHandler):
    server_version = "TP3Lab/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        if self.path == "/api/state":
            self._json(200, LAB.snapshot())
            return
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        content = (WEB_ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                raise ValueError("Requisição muito grande.")
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/server/start":
                result = LAB.call(LAB.start_server())
            elif self.path == "/api/server/stop":
                result = LAB.call(LAB.stop_server())
            elif self.path == "/api/clients":
                result = LAB.call(LAB.create_client(str(body.get("label", ""))))
            elif self.path == "/api/clients/disconnect":
                result = LAB.call(LAB.disconnect_client(str(body.get("id", ""))))
            elif self.path == "/api/messages":
                result = LAB.call(
                    LAB.send_message(
                        str(body.get("sender", "")),
                        str(body.get("recipient", "")),
                        str(body.get("text", "")),
                        body.get("attack"),
                    )
                )
            elif self.path == "/api/framing/invalid":
                result = LAB.call(LAB.send_invalid_framing())
            else:
                self.send_error(404)
                return
            self._json(200, result)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            logger.exception("web action failed")
            self._json(500, {"error": str(exc)})

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("web %s", fmt % args)


def main() -> None:
    parser = argparse.ArgumentParser(description="Interface web local para estudar o protocolo TP3")
    parser.add_argument("--host", default="127.0.0.1", help="endereço HTTP local (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="porta inicial da interface (padrão: 8080)")
    parser.add_argument(
        "--fallback-ports",
        type=int,
        default=20,
        help="quantas portas seguintes tentar se a inicial estiver ocupada (padrão: 20)",
    )
    args = parser.parse_args()
    if args.port < 0 or args.port > 65535 or args.fallback_ports < 0:
        parser.error("--port deve estar entre 0 e 65535 e --fallback-ports não pode ser negativo")

    httpd = None
    last_error = None
    ports = [args.port] if args.port == 0 else range(args.port, min(args.port + args.fallback_ports, 65535) + 1)
    for candidate_port in ports:
        try:
            httpd = ThreadingHTTPServer((args.host, candidate_port), Handler)
            break
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            last_error = exc
            logger.warning("porta %s ocupada; tentando a próxima", candidate_port)
    if httpd is None:
        raise SystemExit(
            f"Nenhuma porta disponível entre {args.port} e "
            f"{min(args.port + args.fallback_ports, 65535)}. "
            "Use --port para escolher outra."
        ) from last_error

    host, port = httpd.server_address[:2]
    logger.info("interface TP3 disponível em http://%s:%s", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("encerrando interface")
    finally:
        try:
            LAB.call(LAB.stop_server(), timeout=4)
        except Exception:
            pass
        httpd.server_close()
        LAB.loop.call_soon_threadsafe(LAB.loop.stop)


if __name__ == "__main__":
    main()
