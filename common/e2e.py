"""E2E message encoding, encryption, and authenticated receive helpers."""

from __future__ import annotations

from asyncio import StreamWriter

from common.crypto import aes_decrypt, aes_encrypt, build_aad_e2e, build_nonce
from common.framing import send_frame
from common.peer import PeerSession
from common.protocol import E2E

MAX_PLAINTEXT = 4096
E2E_HEADER_LENGTH = 12 + 16 + 16 + 8
_TAG_LENGTH = 16
_MAX_SEQ = (1 << 64) - 1


class E2EProtocolError(ValueError):
    """Raised when an E2E message has invalid addressing or encoding."""


class E2EReplayError(E2EProtocolError):
    """Raised when an E2E sequence has already been accepted."""


async def send_e2e(
    writer: StreamWriter,
    sender_id: bytes,
    recipient_id: bytes,
    peer: PeerSession,
    plaintext: bytes,
) -> bytes:
    """Encrypt and send one E2E frame, returning the exact relay payload."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) > MAX_PLAINTEXT:
        raise E2EProtocolError(f"plaintext exceeds {MAX_PLAINTEXT} bytes")
    if len(sender_id) != 16 or len(recipient_id) != 16:
        raise E2EProtocolError("sender and recipient IDs must be exactly 16 bytes")

    async with peer.send_lock:
        seq = peer.seq_send
        if seq > _MAX_SEQ:
            raise OverflowError("E2E send sequence exhausted")
        nonce = build_nonce(peer.iv_base_send, seq)
        aad = build_aad_e2e(sender_id, recipient_id, seq)
        ciphertext = aes_encrypt(peer.key_send, nonce, aad, plaintext)
        payload = nonce + sender_id + recipient_id + seq.to_bytes(8, "big") + ciphertext
        await send_frame(writer, E2E, payload)
        peer.seq_send = seq + 1
        return payload


def receive_e2e(
    own_id: bytes,
    peers: dict[bytes, PeerSession],
    payload: bytes,
) -> tuple[bytes, bytes]:
    """Authenticate an E2E payload and return its sender ID and plaintext."""
    if len(payload) < E2E_HEADER_LENGTH + _TAG_LENGTH:
        raise E2EProtocolError("E2E payload is truncated")

    nonce = payload[:12]
    sender_id = payload[12:28]
    recipient_id = payload[28:44]
    seq = int.from_bytes(payload[44:52], "big")
    if recipient_id != own_id:
        raise E2EProtocolError("E2E recipient does not match this client")

    peer = peers.get(sender_id)
    if peer is None:
        raise E2EProtocolError("E2E sender is not a known peer")
    if seq <= peer.seq_recv:
        raise E2EReplayError(f"E2E replay: seq={seq}")

    aad = build_aad_e2e(sender_id, recipient_id, seq)
    plaintext = aes_decrypt(peer.key_recv, nonce, aad, payload[E2E_HEADER_LENGTH:])
    peer.seq_recv = seq
    return sender_id, plaintext
