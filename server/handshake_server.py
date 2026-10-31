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
        shared_secret = ecdh(server_handshake.server_private_key, server_handshake.client_public_key)
        key_c2s = hkdf_extract_expand(server_handshake.salt_srv, shared_secret, b"C2S")
        key_s2c = hkdf_extract_expand(server_handshake.salt_srv, shared_secret, b"S2C")
        del shared_secret

        session = {
            "writer": writer,
            "public_key": server_handshake.client_public_key,
            "salt": server_handshake.salt_srv,
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
        # The server ephemeral private key is no longer needed after deriving
        # the administrative keys; keep only the connection state and keys.
        server_handshake = None
        async with active_lock:
            previous = active_sessions.get(handshake_client_id)
            if previous is not None:
                # Replacing the map entry first makes the old handler's finally
                # block unable to remove the new authenticated session.
                previous["writer"].close()
                logger.info("sessão substituída: client_id=%s", handshake_client_id.hex())
            active_sessions[handshake_client_id] = session
            logger.info("handshake autenticado: client_id=%s peer=%s", handshake_client_id.hex(), peer)
            # Keep registration and initial sends atomic with respect to other
            # arrivals so the registration confirmation is always seq 0.
            await admin.send_admin(ERROR, b"Registro confirmado")
            # The new client learns about each existing session, and each
            # existing client learns about the new one. AdminChannel serializes
            # sequence allocation and writes for each connection.
            for peer_id, peer_session in tuple(active_sessions.items()):
                if peer_id == handshake_client_id:
                    continue
                await admin.send_admin(
                    PEER_INFO,
                    encode_peer_info(peer_id, peer_session["public_key"], peer_session["salt"]),
                )
                await peer_session["admin"].send_admin(
                    PEER_INFO,
                    encode_peer_info(
                        handshake_client_id,
                        session["public_key"],
                        session["salt"],
                    ),
                )
        while True:
            message_type, payload = await recv_frame(reader)
            if message_type != E2E:
                raise FrameError(f"unexpected client frame type 0x{message_type:02x}")
            await relay_e2e_frame(
                handshake_client_id,
                payload,
                admin,
                active_sessions,
                active_lock,
            )
    except (IncompleteReadError, FrameError, HandshakeError, InvalidKey, OSError) as exc:
        logger.info("handshake rejeitado (%s): peer=%s", exc, peer)
    except (TypeError, ValueError) as exc:
        logger.info("handshake rejeitado (%s): peer=%s", exc, peer)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        if handshake_client_id is not None:
            async with active_lock:
                current = active_sessions.get(handshake_client_id)
                if current is session:
                    active_sessions.pop(handshake_client_id, None)
                    logger.info("desconexão: client_id=%s", handshake_client_id.hex())
                    for peer_id, peer_session in tuple(active_sessions.items()):
                        try:
                            await peer_session["admin"].send_admin(
                                PEER_LEFT, encode_peer_left(handshake_client_id)
                            )
                        except (ConnectionError, OSError):
                            logger.info("falha ao notificar saída: client_id=%s", peer_id.hex())
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
