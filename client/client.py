"""Client-side server-authenticated handshake."""

from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from asyncio import StreamReader, StreamWriter
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from common.crypto import gen_x25519
from common.framing import FrameError, recv_frame, send_frame
from common.protocol import (
    HELLO,
    SERVER_HELLO,
    decode_server_hello,
    encode_hello,
    handshake_digest,
)

logger = logging.getLogger("tp3.client")


class HandshakeError(ValueError):
    """Raised when the server cannot be authenticated."""


@dataclass(frozen=True)
class ClientHandshake:
    """Authenticated connection state retained for the next protocol stage."""

    client_id: bytes
    private_key: X25519PrivateKey
    public_key: bytes
    server_public_key: bytes
    salt_srv: bytes
    certificate_der: bytes
    reader: StreamReader
    writer: StreamWriter


def certificate_to_der(certificate_bytes: bytes) -> bytes:
    """Parse a PEM or DER certificate and return its canonical DER bytes."""
    if not isinstance(certificate_bytes, bytes):
        raise TypeError("certificate must be bytes")
    try:
        if b"-----BEGIN CERTIFICATE-----" in certificate_bytes:
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
        else:
            certificate = x509.load_der_x509_certificate(certificate_bytes)
    except ValueError as exc:
        raise HandshakeError("pinned server certificate is invalid") from exc
    return certificate.public_bytes(serialization.Encoding.DER)


def verify_server_hello(
    pk_server: bytes,
    salt_srv: bytes,
    signature: bytes,
    certificate_der: bytes,
    pinned_certificate_der: bytes,
    pk_client: bytes,
    client_id: bytes,
) -> None:
    """Require the pinned certificate and verify the RSA-PSS handshake signature."""
    if certificate_der != pinned_certificate_der:
        raise HandshakeError("server certificate does not match the pinned certificate")

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise HandshakeError("server sent an invalid certificate") from exc

    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise HandshakeError("pinned certificate does not contain an RSA public key")
    if public_key.key_size < 2048:
        raise HandshakeError("server RSA key must be at least 2048 bits")

    digest = handshake_digest(pk_server, pk_client, client_id, salt_srv)
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            Prehashed(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise HandshakeError("server handshake signature is invalid") from exc


async def perform_client_handshake(
    reader: StreamReader,
    writer: StreamWriter,
    pinned_certificate: bytes,
) -> ClientHandshake:
    """Send HELLO and authenticate SERVER_HELLO against the local certificate pin."""
    private_key, public_key = gen_x25519()
    client_id = uuid.uuid4().bytes

    try:
        pinned_der = certificate_to_der(pinned_certificate)
        await send_frame(writer, HELLO, encode_hello(client_id, public_key))
        message_type, payload = await recv_frame(reader)
        if message_type != SERVER_HELLO:
            raise HandshakeError(f"expected SERVER_HELLO, received type 0x{message_type:02x}")

        try:
            pk_server, salt_srv, signature, certificate_der = decode_server_hello(payload)
        except (TypeError, ValueError) as exc:
            raise HandshakeError("invalid SERVER_HELLO payload") from exc

        verify_server_hello(
            pk_server,
            salt_srv,
            signature,
            certificate_der,
            pinned_der,
            public_key,
            client_id,
        )
        return ClientHandshake(
            client_id=client_id,
            private_key=private_key,
            public_key=public_key,
            server_public_key=pk_server,
            salt_srv=salt_srv,
            certificate_der=certificate_der,
            reader=reader,
            writer=writer,
        )
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        raise


async def connect_and_handshake(
    host: str,
    port: int,
    pinned_certificate_path: str | Path,
) -> ClientHandshake:
    """Open a TCP connection and perform the authenticated handshake."""
    pinned_certificate = Path(pinned_certificate_path).read_bytes()
    reader, writer = await asyncio.open_connection(host, port)
    try:
        return await perform_client_handshake(reader, writer, pinned_certificate)
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        raise


async def _run_cli(host: str, port: int, pin_path: str) -> None:
    connection = await connect_and_handshake(host, port, pin_path)
    print(f"Handshake autenticado com sucesso. client_id={uuid.UUID(bytes=connection.client_id)}")
    connection.writer.close()
    await connection.writer.wait_closed()


def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente de handshake autenticado TP3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--pin", default="client/certs/server.crt")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(_run_cli(args.host, args.port, args.pin))
    except KeyboardInterrupt:
        logger.info("cliente interrompido")
    except (HandshakeError, FrameError, OSError) as exc:
        logger.error("handshake falhou: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
