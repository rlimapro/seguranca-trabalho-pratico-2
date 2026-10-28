"""Wire message types and encoders for the TP3 protocol."""

from __future__ import annotations

import hashlib

HELLO = 0x01
SERVER_HELLO = 0x02
PEER_INFO = 0x03
PEER_LEFT = 0x04
E2E = 0x05
ERROR = 0x06

CLIENT_ID_LENGTH = 16
X25519_PUBLIC_KEY_LENGTH = 32
SERVER_SALT_LENGTH = 16
_U16_MAX = (1 << 16) - 1


def encode_hello(client_id: bytes, pk_client: bytes) -> bytes:
    """Encode HELLO payload as ``client_id | pk_client``."""
    _require_length("client_id", client_id, CLIENT_ID_LENGTH)
    _require_length("pk_client", pk_client, X25519_PUBLIC_KEY_LENGTH)
    return client_id + pk_client


def decode_hello(payload: bytes) -> tuple[bytes, bytes]:
    """Decode a HELLO payload, requiring its exact 48-byte size."""
    if not isinstance(payload, bytes):
        raise TypeError("HELLO payload must be bytes")
    expected_length = CLIENT_ID_LENGTH + X25519_PUBLIC_KEY_LENGTH
    if len(payload) != expected_length:
        raise ValueError(f"HELLO payload must be exactly {expected_length} bytes")
    return payload[:CLIENT_ID_LENGTH], payload[CLIENT_ID_LENGTH:]


def encode_server_hello(
    pk_server: bytes,
    salt_srv: bytes,
    signature: bytes,
    certificate_der: bytes,
) -> bytes:
    """Encode SERVER_HELLO fields with 16-bit big-endian variable lengths."""
    _require_length("pk_server", pk_server, X25519_PUBLIC_KEY_LENGTH)
    _require_length("salt_srv", salt_srv, SERVER_SALT_LENGTH)
    _require_bytes("signature", signature)
    _require_bytes("certificate_der", certificate_der)
    if not signature:
        raise ValueError("signature cannot be empty")
    if not certificate_der:
        raise ValueError("certificate cannot be empty")
    if len(signature) > _U16_MAX or len(certificate_der) > _U16_MAX:
        raise ValueError("signature and certificate lengths must fit in 2 bytes")

    return (
        pk_server
        + salt_srv
        + len(signature).to_bytes(2, "big")
        + signature
        + len(certificate_der).to_bytes(2, "big")
        + certificate_der
    )


def decode_server_hello(payload: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Decode and validate the variable-length SERVER_HELLO payload."""
    if not isinstance(payload, bytes):
        raise TypeError("SERVER_HELLO payload must be bytes")
    fixed_length = X25519_PUBLIC_KEY_LENGTH + SERVER_SALT_LENGTH
    if len(payload) < fixed_length + 4:
        raise ValueError("SERVER_HELLO payload is truncated")

    offset = 0
    pk_server = payload[offset : offset + X25519_PUBLIC_KEY_LENGTH]
    offset += X25519_PUBLIC_KEY_LENGTH
    salt_srv = payload[offset : offset + SERVER_SALT_LENGTH]
    offset += SERVER_SALT_LENGTH

    signature_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    if signature_length == 0 or offset + signature_length + 2 > len(payload):
        raise ValueError("SERVER_HELLO signature length is invalid")
    signature = payload[offset : offset + signature_length]
    offset += signature_length

    certificate_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    if certificate_length == 0 or offset + certificate_length != len(payload):
        raise ValueError("SERVER_HELLO certificate length is invalid")
    certificate_der = payload[offset:]
    return pk_server, salt_srv, signature, certificate_der


def handshake_digest(
    pk_server: bytes,
    pk_client: bytes,
    client_id: bytes,
    salt_srv: bytes,
) -> bytes:
    """Hash the ordered handshake transcript that the server signs."""
    _require_length("pk_server", pk_server, X25519_PUBLIC_KEY_LENGTH)
    _require_length("pk_client", pk_client, X25519_PUBLIC_KEY_LENGTH)
    _require_length("client_id", client_id, CLIENT_ID_LENGTH)
    _require_length("salt_srv", salt_srv, SERVER_SALT_LENGTH)
    return hashlib.sha256(pk_server + pk_client + client_id + salt_srv).digest()


def encode_peer_info(client_id: bytes, public_key: bytes, salt_srv: bytes) -> bytes:
    """Encode the fixed-size rendezvous payload: id | X25519 key | salt."""
    _require_length("client_id", client_id, CLIENT_ID_LENGTH)
    _require_length("public_key", public_key, X25519_PUBLIC_KEY_LENGTH)
    _require_length("salt_srv", salt_srv, SERVER_SALT_LENGTH)
    return client_id + public_key + salt_srv


def decode_peer_info(payload: bytes) -> tuple[bytes, bytes, bytes]:
    """Decode a PEER_INFO plaintext, requiring its exact 64-byte size."""
    if not isinstance(payload, bytes):
        raise TypeError("PEER_INFO payload must be bytes")
    expected = CLIENT_ID_LENGTH + X25519_PUBLIC_KEY_LENGTH + SERVER_SALT_LENGTH
    if len(payload) != expected:
        raise ValueError(f"PEER_INFO payload must be exactly {expected} bytes")
    return payload[:16], payload[16:48], payload[48:]


def encode_peer_left(client_id: bytes) -> bytes:
    """Encode a PEER_LEFT plaintext containing one client identifier."""
    _require_length("client_id", client_id, CLIENT_ID_LENGTH)
    return client_id


def decode_peer_left(payload: bytes) -> bytes:
    """Decode a PEER_LEFT plaintext, requiring an exact 16-byte ID."""
    _require_length("client_id", payload, CLIENT_ID_LENGTH)
    return payload


def _require_length(name: str, value: bytes, expected: int) -> None:
    _require_bytes(name, value)
    if len(value) != expected:
        raise ValueError(f"{name} must be exactly {expected} bytes")


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
