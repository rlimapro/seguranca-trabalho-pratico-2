"""Authenticated X25519/RSA handshake endpoint."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from asyncio import IncompleteReadError, StreamReader, StreamWriter
from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from common.admin import AdminChannel
from common.crypto import ecdh, hkdf_extract_expand
from common.framing import FrameError, recv_frame, send_frame
from common.protocol import (
    E2E,
    ERROR,
    HELLO,
    PEER_INFO,
    PEER_LEFT,
    REGISTERED,
    SERVER_HELLO,
    decode_hello,
    encode_server_hello,
    encode_peer_info,
    encode_peer_left,
    handshake_digest,
)

logger = logging.getLogger("tp3.handshake_server")
sessions: dict[bytes, dict] = {}
sessions_lock = asyncio.Lock()
_E2E_HEADER_LENGTH = 12 + 16 + 16 + 8
_E2E_TAG_LENGTH = 16


class ConnectionLimiter:
    """Count accepted handlers and reject connections beyond a configured cap."""

    def __init__(self, maximum: int):
        if isinstance(maximum, bool) or maximum < 1:
            raise ValueError("maximum connections must be positive")
        self.maximum = maximum
        self.active = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self.active >= self.maximum:
                return False
            self.active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            self.active -= 1


async def relay_e2e_frame(
    sender_id: bytes,
    payload: bytes,
    sender_admin: AdminChannel,
    session_store: dict[bytes, dict],
    session_lock: asyncio.Lock,
) -> bool:
    """Forward an opaque E2E payload to its addressed recipient unchanged."""
    if len(payload) < _E2E_HEADER_LENGTH + _E2E_TAG_LENGTH:
        raise FrameError("E2E payload is truncated")
    if payload[12:28] != sender_id:
        raise FrameError("E2E sender ID does not match the authenticated session")

    recipient_id = payload[28:44]
    async with session_lock:
        recipient = session_store.get(recipient_id)
        if recipient is None:
            await sender_admin.send_admin(ERROR, "Destinatário indisponível".encode("utf-8"))
            return False
        await send_frame(recipient["writer"], E2E, payload)
    return True


class HandshakeError(ValueError):
    """Raised when the peer sends an invalid handshake message."""


def _is_clean_frame_eof(exc: IncompleteReadError) -> bool:
    """Return whether the peer closed between frames, before a new prefix."""
    return exc.expected == 4 and not exc.partial


@dataclass(frozen=True)
class ServerHandshake:
    """Per-connection values retained for the following protocol stage."""

    client_id: bytes
    client_public_key: bytes
    server_private_key: X25519PrivateKey
    server_public_key: bytes
    salt_srv: bytes


def load_server_credentials(
    certificate_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
) -> tuple[bytes, rsa.RSAPrivateKey]:
    """Load a PEM certificate/key pair and ensure they match and use RSA-2048+."""
    certificate_pem = Path(certificate_path).read_bytes()
    private_key_pem = Path(private_key_path).read_bytes()
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("server private key must be RSA")
    certificate_public_key = certificate.public_key()
    if not isinstance(certificate_public_key, rsa.RSAPublicKey):
        raise ValueError("server certificate must contain an RSA public key")
    if private_key.key_size < 2048:
        raise ValueError("server RSA key must be at least 2048 bits")
    if private_key.public_key().public_numbers() != certificate_public_key.public_numbers():
        raise ValueError("server certificate and private key do not match")

    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    return certificate_der, private_key


def create_server_hello(
    client_id: bytes,
    client_public_key: bytes,
    signing_key: rsa.RSAPrivateKey,
    certificate_der: bytes,
) -> tuple[bytes, ServerHandshake]:
    """Create a signed SERVER_HELLO and the ephemeral server-side state."""
    server_private_key = X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    salt_srv = os.urandom(16)
    digest = handshake_digest(server_public_key, client_public_key, client_id, salt_srv)
    signature = signing_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        Prehashed(hashes.SHA256()),
    )
    payload = encode_server_hello(server_public_key, salt_srv, signature, certificate_der)
    session = ServerHandshake(
        client_id=client_id,
        client_public_key=client_public_key,
        server_private_key=server_private_key,
        server_public_key=server_public_key,
        salt_srv=salt_srv,
    )
    return payload, session


async def perform_server_handshake(
    reader: StreamReader,
    writer: StreamWriter,
    signing_key: rsa.RSAPrivateKey,
    certificate_der: bytes,
) -> ServerHandshake:
    """Receive HELLO, send the signed SERVER_HELLO, and return session material."""
    message_type, payload = await recv_frame(reader)
    if message_type != HELLO:
        raise HandshakeError(f"expected HELLO, received type 0x{message_type:02x}")

    try:
        client_id, client_public_key = decode_hello(payload)
    except (TypeError, ValueError) as exc:
        raise HandshakeError("invalid HELLO payload") from exc

    response, session = create_server_hello(
        client_id,
        client_public_key,
        signing_key,
        certificate_der,
    )
    await send_frame(writer, SERVER_HELLO, response)
    return session


def establish_admin_session(
    reader: StreamReader,
    writer: StreamWriter,
    handshake: ServerHandshake,
) -> tuple[dict, AdminChannel]:
    """Derive the administrative keys and build this connection's state."""
    shared_secret = ecdh(handshake.server_private_key, handshake.client_public_key)
    key_c2s = hkdf_extract_expand(handshake.salt_srv, shared_secret, b"C2S")
    key_s2c = hkdf_extract_expand(handshake.salt_srv, shared_secret, b"S2C")
    del shared_secret

    session = {
        "writer": writer,
        "public_key": handshake.client_public_key,
        "salt": handshake.salt_srv,
        "seq_send": 0,
        "seq_recv": -1,
    }
    admin = AdminChannel(
        reader,
        writer,
        key_send=key_s2c,
        key_recv=key_c2s,
        direction_send=1,
        direction_recv=0,
        sequence_state=session,
    )
    session["admin"] = admin
    return session, admin


async def register_session(
    client_id: bytes,
    session: dict,
    session_store: dict[bytes, dict],
    session_lock: asyncio.Lock,
    peer: object,
) -> None:
    """Install a session and send its confirmation and initial peer list."""
    async with session_lock:
        previous = session_store.get(client_id)
        if previous is not None:
            # Replacing the map entry first prevents the old handler from
            # removing this new session in its finally block.
            previous["writer"].close()
            logger.info("sessão substituída: client_id=%s", client_id.hex())
        session_store[client_id] = session
        logger.info("handshake autenticado: client_id=%s peer=%s", client_id.hex(), peer)

        # Keep registration and initial sends atomic: REGISTERED must use seq 0.
        await session["admin"].send_admin(REGISTERED, b"Registro confirmado")
        for peer_id, peer_session in tuple(session_store.items()):
            if peer_id == client_id:
                continue
            await session["admin"].send_admin(
                PEER_INFO,
                encode_peer_info(peer_id, peer_session["public_key"], peer_session["salt"]),
            )
            await peer_session["admin"].send_admin(
                PEER_INFO,
                encode_peer_info(client_id, session["public_key"], session["salt"]),
            )


async def relay_client_messages(
    reader: StreamReader,
    client_id: bytes,
    admin: AdminChannel,
    session_store: dict[bytes, dict],
    session_lock: asyncio.Lock,
) -> None:
    """Receive E2E frames from one client and relay them unchanged."""
    while True:
        message_type, payload = await recv_frame(reader)
        if message_type != E2E:
            raise FrameError(f"unexpected client frame type 0x{message_type:02x}")
        await relay_e2e_frame(client_id, payload, admin, session_store, session_lock)


async def cleanup_client_session(
    writer: StreamWriter,
    client_id: bytes | None,
    session: dict | None,
    session_store: dict[bytes, dict],
    session_lock: asyncio.Lock,
) -> None:
    """Close a connection and remove/announce its session if still current."""
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass

    if client_id is None:
        return
    async with session_lock:
        current = session_store.get(client_id)
        if current is session:
            session_store.pop(client_id, None)
            logger.info("desconexão: client_id=%s", client_id.hex())
            for peer_id, peer_session in tuple(session_store.items()):
                try:
                    await peer_session["admin"].send_admin(
                        PEER_LEFT, encode_peer_left(client_id)
                    )
                except (ConnectionError, OSError):
                    logger.info("falha ao notificar saída: client_id=%s", peer_id.hex())


async def handle_handshake_client(
    reader: StreamReader,
    writer: StreamWriter,
    signing_key: rsa.RSAPrivateKey,
    certificate_der: bytes,
    session_store: dict[bytes, dict] | None = None,
    session_lock: asyncio.Lock | None = None,
    connection_limiter: ConnectionLimiter | None = None,
) -> None:
    """Handle handshake, establish the admin channel, and retain the session."""
    peer = writer.get_extra_info("peername")
    active_sessions = session_store if session_store is not None else sessions
    active_lock = session_lock if session_lock is not None else sessions_lock
    server_handshake: ServerHandshake | None = None
    handshake_client_id: bytes | None = None
    session: dict | None = None
    limiter_acquired = False
    try:
        if connection_limiter is not None:
            limiter_acquired = await connection_limiter.acquire()
            if not limiter_acquired:
                logger.warning("conexão recusada: motivo=limite de conexões")
                return
        server_handshake = await perform_server_handshake(reader, writer, signing_key, certificate_der)
        handshake_client_id = server_handshake.client_id
        session, admin = establish_admin_session(reader, writer, server_handshake)
        # The server ephemeral private key is no longer needed after deriving
        # the administrative keys; keep only the connection state and keys.
        server_handshake = None
        await register_session(handshake_client_id, session, active_sessions, active_lock, peer)
        await relay_client_messages(reader, handshake_client_id, admin, active_sessions, active_lock)
    except IncompleteReadError as exc:
        if _is_clean_frame_eof(exc):
            if handshake_client_id is None:
                logger.info("conexão encerrada antes do HELLO: peer=%s", peer)
            # Once registered, cleanup_client_session logs the normal disconnect.
        else:
            logger.info("conexão encerrada com frame truncado: peer=%s", peer)
    except (FrameError, HandshakeError, InvalidKey, OSError) as exc:
        logger.info("handshake rejeitado (%s): peer=%s", exc, peer)
    except (TypeError, ValueError) as exc:
        logger.info("handshake rejeitado (%s): peer=%s", exc, peer)
    finally:
        try:
            await cleanup_client_session(
                writer, handshake_client_id, session, active_sessions, active_lock
            )
        finally:
            if limiter_acquired and connection_limiter is not None:
                await connection_limiter.release()


async def serve(
    host: str = "127.0.0.1",
    port: int = 8766,
    certificate_path: str | os.PathLike[str] = "certs/server.crt",
    private_key_path: str | os.PathLike[str] = "certs/server.key",
    max_connections: int = 100,
) -> None:
    certificate_der, signing_key = load_server_credentials(certificate_path, private_key_path)
    limiter = ConnectionLimiter(max_connections)

    server = await asyncio.start_server(
        lambda reader, writer: handle_handshake_client(
            reader,
            writer,
            signing_key,
            certificate_der,
            sessions,
            sessions_lock,
            limiter,
        ),
        host,
        port,
    )
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logger.info("servidor de handshake ouvindo em %s", addresses)

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor de handshake autenticado TP3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--cert", default="certs/server.crt")
    parser.add_argument("--key", default="certs/server.key")
    parser.add_argument("--max-connections", type=int, default=100)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(args.host, args.port, args.cert, args.key, args.max_connections))
    except KeyboardInterrupt:
        logger.info("servidor interrompido")


if __name__ == "__main__":
    main()
