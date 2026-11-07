"""Client-side server-authenticated handshake."""

from __future__ import annotations

import argparse
import asyncio
import colorsys
import hashlib
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from html import escape

from asyncio import StreamReader, StreamWriter
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from prompt_toolkit import PromptSession
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.patch_stdout import patch_stdout

from common.admin import ADMIN_TYPES, AdminChannel
from common.crypto import ecdh, fingerprint, gen_x25519, hkdf_extract_expand
from common.e2e import (
    E2EAuthenticationError,
    E2EProtocolError,
    E2EReplayError,
    receive_e2e,
    send_e2e,
)
from common.framing import FrameError, recv_frame, send_frame
from common.peer import PeerSession, derive_peer_session
from common.protocol import (
    ERROR,
    E2E,
    HELLO,
    PEER_INFO,
    PEER_LEFT,
    REGISTERED,
    SERVER_HELLO,
    decode_peer_info,
    decode_peer_left,
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


@dataclass(frozen=True)
class AdminClientConnection:
    """Authenticated administrative channel and its registration notice."""

    channel: AdminChannel
    confirmation: bytes
    known_peers: dict[bytes, tuple[bytes, bytes]]
    peers: dict[bytes, PeerSession]


def apply_peer_event(
    handshake: ClientHandshake,
    known_peers: dict[bytes, tuple[bytes, bytes]],
    peers: dict[bytes, PeerSession],
    message_type: int,
    plaintext: bytes,
) -> tuple[bytes, str] | None:
    """Update peer metadata and derived E2E keys; return a displayable event."""
    if message_type == PEER_INFO:
        peer_id, public_key, salt = decode_peer_info(plaintext)
        if peer_id == handshake.client_id:
            raise ValueError("server sent this client's own identity as a peer")
        peer_session = derive_peer_session(
            handshake.client_id,
            peer_id,
            handshake.private_key,
            public_key,
            handshake.salt_srv,
            salt,
        )
        known_peers[peer_id] = (public_key, salt)
        peers[peer_id] = peer_session
        return peer_id, fingerprint(public_key)
    if message_type == PEER_LEFT:
        peer_id = decode_peer_left(plaintext)
        known_peers.pop(peer_id, None)
        peers.pop(peer_id, None)
        return peer_id, "left"
    if message_type in (ERROR, REGISTERED):
        return None
    raise ValueError(f"unexpected administrative message 0x{message_type:02x}")


def resolve_peer_prefix(prefix: str, peer_ids: set[bytes]) -> bytes:
    """Resolve a UUID, UUID prefix, or hex prefix to one known peer ID."""
    normalized = prefix.strip().lower().replace("-", "")
    if not normalized:
        raise ValueError("informe o ID ou prefixo do destinatário")
    matches = [peer_id for peer_id in peer_ids if peer_id.hex().startswith(normalized)]
    if not matches:
        raise ValueError("nenhum peer corresponde a esse ID")
    if len(matches) > 1:
        raise ValueError("prefixo ambíguo; informe mais caracteres do ID")
    return matches[0]


async def send_to_peer(
    handshake: ClientHandshake,
    admin: AdminClientConnection,
    command: str,
    attack: str | None = None,
) -> tuple[bytes, int, bytes]:
    """Parse ``/to <id-or-prefix> <message>`` and send it E2E."""
    parts = command.split(maxsplit=2)
    if len(parts) != 3 or parts[0] != "/to":
        raise ValueError("uso: /to <id_ou_prefixo> mensagem")
    peer_id = resolve_peer_prefix(parts[1], set(admin.peers))
    payload = await send_e2e(
        handshake.writer,
        handshake.client_id,
        peer_id,
        admin.peers[peer_id],
        parts[2].encode("utf-8"),
        attack=attack,
    )
    seq = int.from_bytes(payload[44:52], "big")
    return peer_id, seq, payload


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


async def establish_admin_channel(handshake: ClientHandshake) -> AdminClientConnection:
    """Derive C2S/S2C keys and receive the server's encrypted confirmation."""
    try:
        shared_secret = ecdh(handshake.private_key, handshake.server_public_key)
        key_c2s = hkdf_extract_expand(handshake.salt_srv, shared_secret, b"C2S")
        key_s2c = hkdf_extract_expand(handshake.salt_srv, shared_secret, b"S2C")
        del shared_secret

        channel = AdminChannel(
            handshake.reader,
            handshake.writer,
            key_send=key_c2s,
            key_recv=key_s2c,
            direction_send=0,
            direction_recv=1,
        )
        message_type, plaintext, _seq = await channel.recv_admin()
        if message_type != REGISTERED:
            raise HandshakeError("server did not send the registration confirmation")
        return AdminClientConnection(
            channel=channel, confirmation=plaintext, known_peers={}, peers={}
        )
    except Exception:
        handshake.writer.close()
        try:
            await handshake.writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        raise


async def _run_cli(host: str, port: int, pin_path: str, attack: str | None = None) -> None:
    handshake = await connect_and_handshake(host, port, pin_path)
    admin = await establish_admin_channel(handshake)
    session = PromptSession()
    with patch_stdout():
        _print_cli(
            "✓  Conectado · handshake autenticado · canal administrativo cifrado",
            "#22c55e",
        )
        _print_cli(
            f"ID  {uuid.UUID(bytes=handshake.client_id)}   ·   "
            f"{admin.confirmation.decode('utf-8', errors='replace')}",
            "#94a3b8",
        )
        _print_cli("Use /to <id ou prefixo> <mensagem> · /exit para sair.", "#64748b")
        if attack is not None:
            _print_cli(f"⚠  Modo de demonstração ativo · {attack}", "#fbbf24")
        receiver = asyncio.create_task(_receive_messages(handshake, admin))
        try:
            while not receiver.done():
                try:
                    command = await session.prompt_async(HTML("<ansigreen>› </ansigreen>"))
                except EOFError:
                    break
                if command.strip().lower() == "/exit":
                    _print_cli("Até logo.", "#94a3b8")
                    break
                try:
                    peer_id, seq, _payload = await send_to_peer(handshake, admin, command, attack)
                    action = f" · {attack}" if attack is not None else ""
                    _print_cli(
                        f"↗  Enviada para {str(uuid.UUID(bytes=peer_id))[:8]} · #{seq}{action}",
                        "#fbbf24" if attack is not None else "#60a5fa",
                    )
                except (ValueError, UnicodeError) as exc:
                    _print_cli(f"!  {exc}", "#fbbf24")
        finally:
            if not receiver.done():
                receiver.cancel()
            await asyncio.gather(receiver, return_exceptions=True)
            handshake.writer.close()
            await handshake.writer.wait_closed()


def _print_cli(message: str, color: str) -> None:
    print_formatted_text(HTML(f"<style fg='{color}'>{escape(message)}</style>"))


def _print_incoming_message(sender_id: bytes, message: str) -> None:
    sender = escape(str(uuid.UUID(bytes=sender_id))[:8])
    body = escape(message)
    # Hash do ID, em vez do hash() embutido do Python, mantém a cor entre execuções.
    hue = int.from_bytes(hashlib.sha256(sender_id).digest()[:2], "big") % 360
    sender_color = _hsl_to_hex(hue, 72, 68)
    print_formatted_text(
        HTML(
            f"<style fg='#2dd4bf'>│</style>  "
            f"<b><style fg='{sender_color}'>{sender}</style></b>  "
            f"<style fg='#64748b'>›</style>  {body}"
        )
    )


def _hsl_to_hex(hue: int, saturation: int, lightness: int) -> str:
    """Convert an HSL color to RGB hex for readable, stable peer colors."""
    red, green, blue = colorsys.hls_to_rgb(
        hue / 360, lightness / 100, saturation / 100
    )
    return "#{:02x}{:02x}{:02x}".format(
        round(red * 255), round(green * 255), round(blue * 255)
    )


async def _receive_messages(
    handshake: ClientHandshake, admin: AdminClientConnection
) -> None:
    """Read and dispatch administrative and E2E frames from the server."""
    while True:
        try:
            message_type, payload = await recv_frame(handshake.reader)
        except (FrameError, asyncio.IncompleteReadError) as exc:
            _print_cli(f"⚠  Conexão encerrada · frame inválido ({exc})", "#f87171")
            handshake.writer.close()
            try:
                await handshake.writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return
        if message_type in ADMIN_TYPES:
            message_type, plaintext, _seq = admin.channel.decode_admin_frame(message_type, payload)
            if message_type == ERROR:
                _print_cli(f"!  Servidor · {plaintext.decode('utf-8', errors='replace')}", "#fbbf24")
                continue
            event = apply_peer_event(
                handshake,
                admin.known_peers,
                admin.peers,
                message_type,
                plaintext,
            )
            if event is not None:
                peer_id, detail = event
                if detail == "left":
                    _print_cli(f"←  Peer desconectou · {uuid.UUID(bytes=peer_id)}", "#94a3b8")
                else:
                    _print_cli(
                        f"●  Peer pronto · {uuid.UUID(bytes=peer_id)} · fingerprint {detail}",
                        "#c084fc",
                    )
        elif message_type == E2E:
            try:
                sender_id, plaintext = receive_e2e(handshake.client_id, admin.peers, payload)
            except E2EReplayError:
                _print_cli("⚠  Mensagem rejeitada · replay detectado", "#fbbf24")
                continue
            except E2EAuthenticationError:
                _print_cli("⚠  Mensagem rejeitada · autenticação inválida", "#f87171")
                continue
            except E2EProtocolError as exc:
                _print_cli(f"⚠  Mensagem rejeitada · {exc}", "#fbbf24")
                continue
            message = plaintext.decode("utf-8", errors="replace")
            _print_incoming_message(sender_id, message)
        else:
            raise FrameError(f"tipo de frame inesperado: 0x{message_type:02x}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente de handshake autenticado TP3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--pin", default="client/certs/server.crt")
    parser.add_argument("--attack", choices=("bitflip", "replay"), help="altera ou repete os frames E2E enviados")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(_run_cli(args.host, args.port, args.pin, args.attack))
    except KeyboardInterrupt:
        logger.info("cliente interrompido")
    except (HandshakeError, FrameError, OSError) as exc:
        logger.error("handshake falhou: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
