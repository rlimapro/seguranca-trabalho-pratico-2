"""Pure cryptographic helpers used by the TP3 protocol."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_LENGTH = 16
_NONCE_LENGTH = 12
_ID_LENGTH = 16
_PUBLIC_KEY_LENGTH = 32
_U64_MAX = (1 << 64) - 1


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _encode_seq(seq: int) -> bytes:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an integer")
    if not 0 <= seq <= _U64_MAX:
        raise ValueError("seq must fit in an unsigned 64-bit integer")
    return seq.to_bytes(8, "big")


def gen_x25519() -> tuple[X25519PrivateKey, bytes]:
    """Generate an X25519 private key and its 32-byte raw public key."""
    private_key = X25519PrivateKey.generate()
    public_key_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key_raw


def ecdh(sk: X25519PrivateKey, pk_peer_raw: bytes) -> bytes:
    """Calculate an X25519 shared secret from a private key and raw peer key."""
    if not isinstance(sk, X25519PrivateKey):
        raise TypeError("sk must be an X25519PrivateKey")
    _require_bytes("pk_peer_raw", pk_peer_raw)
    if len(pk_peer_raw) != _PUBLIC_KEY_LENGTH:
        raise ValueError("an X25519 raw public key must be exactly 32 bytes")

    peer_key = X25519PublicKey.from_public_bytes(pk_peer_raw)
    return sk.exchange(peer_key)


def hkdf_extract_expand(
    salt: bytes,
    ikm: bytes,
    info: bytes,
    length: int = _KEY_LENGTH,
) -> bytes:
    """Derive key material with HKDF-SHA256 (extract followed by expand)."""
    _require_bytes("salt", salt)
    _require_bytes("ikm", ikm)
    _require_bytes("info", info)
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length <= 0:
        raise ValueError("length must be positive")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def build_nonce(iv_base_or_direction: bytes | int, seq: int) -> bytes:
    """Build a 12-byte nonce: a 4-byte prefix followed by an 8-byte sequence.

    A byte prefix must already be exactly 4 bytes. An integer prefix, such as
    administrative direction 0 or 1, is encoded as an unsigned 4-byte
    big-endian value.
    """
    if isinstance(iv_base_or_direction, int) and not isinstance(iv_base_or_direction, bool):
        if not 0 <= iv_base_or_direction <= 0xFFFFFFFF:
            raise ValueError("integer nonce prefix must fit in 4 bytes")
        prefix = iv_base_or_direction.to_bytes(4, "big")
    else:
        _require_bytes("iv_base_or_direction", iv_base_or_direction)
        prefix = iv_base_or_direction
        if len(prefix) != 4:
            raise ValueError("nonce prefix must be exactly 4 bytes")

    return prefix + _encode_seq(seq)


def build_aad_e2e(sender: bytes, recipient: bytes, seq: int) -> bytes:
    """Build E2E AAD as ``sender_id | recipient_id | seq_no``."""
    _require_bytes("sender", sender)
    _require_bytes("recipient", recipient)
    if len(sender) != _ID_LENGTH or len(recipient) != _ID_LENGTH:
        raise ValueError("sender and recipient IDs must be exactly 16 bytes")
    return sender + recipient + _encode_seq(seq)


def build_aad_admin(frame_type: int, seq: int) -> bytes:
    """Build administrative AAD as ``type(1B) | seq(8B BE)``."""
    if isinstance(frame_type, bool) or not isinstance(frame_type, int):
        raise TypeError("frame_type must be an integer")
    if not 0 <= frame_type <= 0xFF:
        raise ValueError("frame_type must fit in one byte")
    return bytes((frame_type,)) + _encode_seq(seq)


def aes_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-128-GCM; return ``ciphertext || tag``."""
    _validate_aes_inputs(key, nonce, aad)
    _require_bytes("plaintext", plaintext)
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext_and_tag: bytes) -> bytes:
    """Decrypt AES-128-GCM data, propagating ``InvalidTag`` on authentication failure."""
    _validate_aes_inputs(key, nonce, aad)
    _require_bytes("ciphertext_and_tag", ciphertext_and_tag)
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)


def _validate_aes_inputs(key: bytes, nonce: bytes, aad: bytes) -> None:
    _require_bytes("key", key)
    _require_bytes("nonce", nonce)
    _require_bytes("aad", aad)
    if len(key) != _KEY_LENGTH:
        raise ValueError("AES-128-GCM key must be exactly 16 bytes")
    if len(nonce) != _NONCE_LENGTH:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")


def fingerprint(pk: bytes) -> str:
    """Return the hexadecimal SHA-256 fingerprint using the first 8 bytes."""
    _require_bytes("pk", pk)
    if len(pk) != _PUBLIC_KEY_LENGTH:
        raise ValueError("an X25519 raw public key must be exactly 32 bytes")
    return hashlib.sha256(pk).digest()[:8].hex()
