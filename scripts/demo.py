"""Run an in-memory three-client demonstration, including all three attacks."""

from __future__ import annotations

import asyncio
import datetime
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from client.client import (
    apply_peer_event,
    establish_admin_channel,
    perform_client_handshake,
)
from common.e2e import E2EAuthenticationError, E2EReplayError, receive_e2e, send_e2e
from common.framing import recv_frame
from common.protocol import E2E
from server.handshake_server import handle_handshake_client


class MemoryWriter:
    """Connect two asyncio streams without opening a network socket."""

    def __init__(self, peer_reader):
        self.peer_reader = peer_reader
        self.closed = False

    def write(self, data):
        self.peer_reader.feed_data(data)

    async def drain(self):
        pass

    def get_extra_info(self, name):
        return ("memory", 0) if name == "peername" else None

    def close(self):
        if not self.closed:
            self.closed = True
            self.peer_reader.feed_eof()

    async def wait_closed(self):
        pass


def create_certificate(signing_key) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "tp3-demo")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(signing_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(signing_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


async def connect_client(signing_key, certificate_der, sessions, lock):
    client_reader = asyncio.StreamReader()
    server_reader = asyncio.StreamReader()
    client_writer = MemoryWriter(server_reader)
    server_writer = MemoryWriter(client_reader)
    task = asyncio.create_task(
        handle_handshake_client(
            server_reader,
            server_writer,
            signing_key,
            certificate_der,
            sessions,
            lock,
        )
    )
    handshake = await perform_client_handshake(client_reader, client_writer, certificate_der)
    admin = await establish_admin_channel(handshake)
    return handshake, admin, client_writer, server_writer, task


async def next_peer(handshake, admin):
    message_type, payload, _seq = await admin.channel.recv_admin()
    return apply_peer_event(handshake, admin.known_peers, admin.peers, message_type, payload)


async def receive_e2e_frame(handshake):
    message_type, payload = await recv_frame(handshake.reader)
    if message_type != E2E:
        raise RuntimeError(f"esperado E2E, recebido 0x{message_type:02x}")
    return payload


async def run() -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate_der = create_certificate(signing_key)
    sessions = {}
    lock = asyncio.Lock()
    clients = []
    try:
        a = await connect_client(signing_key, certificate_der, sessions, lock)
        clients.append(a)
        b = await connect_client(signing_key, certificate_der, sessions, lock)
        clients.append(b)
        await next_peer(a[0], a[1])
        await next_peer(b[0], b[1])
        c = await connect_client(signing_key, certificate_der, sessions, lock)
        clients.append(c)
        await next_peer(c[0], c[1])
        await next_peer(c[0], c[1])
        await next_peer(a[0], a[1])
        await next_peer(b[0], b[1])
        print("Três clientes registrados; Alice e Bruno derivaram chaves E2E.")

        ah, aa = a[:2]
        bh, ba = b[:2]
        peer_a = aa.peers[bh.client_id]

        await send_e2e(ah.writer, ah.client_id, bh.client_id, peer_a, b"oi, Bruno")
        normal = await receive_e2e_frame(bh)
        print("Normal:", receive_e2e(bh.client_id, ba.peers, normal)[1].decode())

        await send_e2e(
            ah.writer, ah.client_id, bh.client_id, peer_a, b"bitflip demonstrativo", attack="bitflip"
        )
        altered = await receive_e2e_frame(bh)
        try:
            receive_e2e(bh.client_id, ba.peers, altered)
        except E2EAuthenticationError:
            print("Bitflip: rejeitado por tag inválida; conexão continua")

        await send_e2e(
            ah.writer, ah.client_id, bh.client_id, peer_a, b"replay demonstrativo", attack="replay"
        )
        original = await receive_e2e_frame(bh)
        repeated = await receive_e2e_frame(bh)
        receive_e2e(bh.client_id, ba.peers, original)
        try:
            receive_e2e(bh.client_id, ba.peers, repeated)
        except E2EReplayError:
            print("Replay: rejeitado por sequência repetida")

        await send_e2e(ah.writer, ah.client_id, bh.client_id, peer_a, "recuperação".encode())
        recovered = await receive_e2e_frame(bh)
        print("Após rejeições:", receive_e2e(bh.client_id, ba.peers, recovered)[1].decode())

        malformed = await connect_client(signing_key, certificate_der, sessions, lock)
        clients.append(malformed)
        malformed[2].write(struct.pack("!I", 0xFFFFFFFF))
        await malformed[4]
        print(
            "Framing inválido:",
            "conexão encerrada" if malformed[3].closed else "inesperadamente aberta",
        )
    finally:
        for _handshake, _admin, client_writer, _server_writer, _task in clients:
            client_writer.close()
        for _handshake, _admin, _client_writer, _server_writer, task in clients:
            if not task.done():
                await task


if __name__ == "__main__":
    asyncio.run(run())
