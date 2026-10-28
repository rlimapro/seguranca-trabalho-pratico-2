"""Client-side E2E key derivation state for one known peer."""

from __future__ import annotations

import asyncio
import hashlib
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from common.crypto import ecdh, hkdf_extract_expand


@dataclass
class PeerSession:
    """Per-peer directional keys and E2E sequence/nonce state."""

    public_key: bytes
    key_send: bytes
    key_recv: bytes
    seq_send: int = 0
    seq_recv: int = -1
    iv_base_send: bytes = b""
    iv_base_recv: bytes | None = None
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)


def derive_peer_session(
    client_id: bytes,
    peer_id: bytes,
    private_key: X25519PrivateKey,
    peer_public_key: bytes,
    own_salt: bytes,
    peer_salt: bytes,
) -> PeerSession:
    """Derive matching A2B/B2A keys and local send state from rendezvous data."""
    if len(client_id) != 16 or len(peer_id) != 16:
        raise ValueError("client IDs must be exactly 16 bytes")
    if client_id == peer_id:
        raise ValueError("a client cannot derive a peer session with itself")
    if len(own_salt) != 16 or len(peer_salt) != 16:
        raise ValueError("server salts must be exactly 16 bytes")

    if client_id < peer_id:
        salt_pair = hashlib.sha256(own_salt + peer_salt).digest()[:16]
    else:
        salt_pair = hashlib.sha256(peer_salt + own_salt).digest()[:16]

    shared_secret = ecdh(private_key, peer_public_key)
    key_a2b = hkdf_extract_expand(salt_pair, shared_secret, b"A2B")
    key_b2a = hkdf_extract_expand(salt_pair, shared_secret, b"B2A")
    del shared_secret

    if client_id < peer_id:
        key_send, key_recv = key_a2b, key_b2a
    else:
        key_send, key_recv = key_b2a, key_a2b
    return PeerSession(
        public_key=peer_public_key,
        key_send=key_send,
        key_recv=key_recv,
        iv_base_send=os.urandom(4),
    )
