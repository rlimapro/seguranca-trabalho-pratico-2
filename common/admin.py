"""Authenticated, sequenced client-server administrative messages."""

from __future__ import annotations

import asyncio
from collections.abc import MutableMapping

from asyncio import StreamReader, StreamWriter
from cryptography.exceptions import InvalidTag

from common.crypto import aes_decrypt, aes_encrypt, build_aad_admin, build_nonce
from common.framing import recv_frame, send_frame
from common.protocol import ERROR, PEER_INFO, PEER_LEFT

ADMIN_TYPES = frozenset((PEER_INFO, PEER_LEFT, ERROR))
_TAG_LENGTH = 16
_SEQ_LENGTH = 8
_MAX_SEQ = (1 << 64) - 1


class AdminProtocolError(ValueError):
    """Raised when an administrative frame has an invalid type or encoding."""


class AdminReplayError(AdminProtocolError):
    """Raised when an administrative sequence number has already been used."""


class AdminChannel:
    """AES-GCM administrative channel with independent send/receive counters.

    ``sequence_state`` can be the server's session dictionary so the counters
    remain visible in ``sessions[client_id]``. Direction prefixes are four-byte
    values: client-to-server is 0 and server-to-client is 1.
    """

    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        key_send: bytes,
        key_recv: bytes,
        direction_send: int,
        direction_recv: int,
        sequence_state: MutableMapping[str, int] | None = None,
    ) -> None:
        if len(key_send) != 16 or len(key_recv) != 16:
            raise ValueError("administrative AES keys must be exactly 16 bytes")
        if direction_send not in (0, 1) or direction_recv not in (0, 1):
            raise ValueError("administrative direction must be 0 or 1")
        self.reader = reader
        self.writer = writer
        self.key_send = key_send
        self.key_recv = key_recv
        self.direction_send = direction_send
        self.direction_recv = direction_recv
        self.sequence_state = sequence_state if sequence_state is not None else {}
        self.sequence_state.setdefault("seq_send", 0)
        self.sequence_state.setdefault("seq_recv", -1)
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()

    @property
    def seq_send(self) -> int:
        return self.sequence_state["seq_send"]

    @property
    def seq_recv(self) -> int:
        return self.sequence_state["seq_recv"]

    async def send_admin(self, message_type: int, plaintext: bytes) -> int:
        """Encrypt and send one admin frame, returning the sequence used."""
        if message_type not in ADMIN_TYPES:
            raise AdminProtocolError(f"type 0x{message_type:02x} is not administrative")

        async with self._send_lock:
            seq = self.seq_send
            if seq > _MAX_SEQ:
                raise OverflowError("administrative send sequence exhausted")
            nonce = build_nonce(self.direction_send, seq)
            aad = build_aad_admin(message_type, seq)
            ciphertext = aes_encrypt(self.key_send, nonce, aad, plaintext)
            await send_frame(self.writer, message_type, seq.to_bytes(_SEQ_LENGTH, "big") + ciphertext)
            self.sequence_state["seq_send"] = seq + 1
            return seq

    async def recv_admin(self) -> tuple[int, bytes, int]:
        """Receive and authenticate an admin frame before advancing its counter."""
        async with self._recv_lock:
            message_type, payload = await recv_frame(self.reader)
            if message_type not in ADMIN_TYPES:
                raise AdminProtocolError(f"type 0x{message_type:02x} is not administrative")
            if len(payload) < _SEQ_LENGTH + _TAG_LENGTH:
                raise AdminProtocolError("administrative payload is truncated")

            seq = int.from_bytes(payload[:_SEQ_LENGTH], "big")
            if seq <= self.seq_recv:
                raise AdminReplayError(f"administrative replay: seq={seq}")

            ciphertext = payload[_SEQ_LENGTH:]
            nonce = build_nonce(self.direction_recv, seq)
            aad = build_aad_admin(message_type, seq)
            # InvalidTag propagates. Crucially, seq_recv changes only after
            # successful authentication and decryption.
            plaintext = aes_decrypt(self.key_recv, nonce, aad, ciphertext)
            self.sequence_state["seq_recv"] = seq
            return message_type, plaintext, seq
