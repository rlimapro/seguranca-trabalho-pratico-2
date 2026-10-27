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

from common.framing import FrameError, recv_frame, send_frame
from common.protocol import (
    HELLO,
    SERVER_HELLO,
    decode_hello,
    encode_server_hello,
    handshake_digest,
)

logger = logging.getLogger("tp3.handshake_server")


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
) -> None:
    """Handle one handshake and keep its TCP connection open until client EOF.

    The current stage has no post-handshake messages. The next stage will
    replace the idle wait with the authenticated administrative channel.
    """
    peer = writer.get_extra_info("peername")
    session: ServerHandshake | None = None
    try:
        session = await perform_server_handshake(reader, writer, signing_key, certificate_der)
        logger.info("handshake autenticado: client_id=%s peer=%s", session.client_id.hex(), peer)
        await reader.read()
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
        # Keep the ephemeral private key alive for this connection's lifetime;
        # it will be used to derive the administrative channel in stage 4.
        session = None


async def serve(
    host: str = "127.0.0.1",
    port: int = 8766,
    certificate_path: str | os.PathLike[str] = "certs/server.crt",
    private_key_path: str | os.PathLike[str] = "certs/server.key",
) -> None:
    certificate_der, signing_key = load_server_credentials(certificate_path, private_key_path)

    server = await asyncio.start_server(
        lambda reader, writer: handle_handshake_client(
            reader,
            writer,
            signing_key,
            certificate_der,
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
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(args.host, args.port, args.cert, args.key))
    except KeyboardInterrupt:
        logger.info("servidor interrompido")


if __name__ == "__main__":
    main()
