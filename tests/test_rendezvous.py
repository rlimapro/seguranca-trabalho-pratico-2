import asyncio
import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from client.client import apply_peer_event, establish_admin_channel, perform_client_handshake
from common.protocol import PEER_INFO, PEER_LEFT
from server.handshake_server import handle_handshake_client


class MemoryWriter:
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


def make_certificate(key):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "rendezvous-test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class RendezvousTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.certificate = make_certificate(self.signing_key)
        self.sessions = {}
        self.lock = asyncio.Lock()
        self.clients = []

    async def connect_client(self):
        client_reader = asyncio.StreamReader()
        server_reader = asyncio.StreamReader()
        client_writer = MemoryWriter(server_reader)
        server_writer = MemoryWriter(client_reader)
        task = asyncio.create_task(
            handle_handshake_client(
                server_reader,
                server_writer,
                self.signing_key,
                self.certificate,
                self.sessions,
                self.lock,
            )
        )
        handshake = await perform_client_handshake(client_reader, client_writer, self.certificate)
        admin = await establish_admin_channel(handshake)
        connection = (handshake, admin, client_writer, task)
        self.clients.append(connection)
        return connection

    async def receive_peer_event(self, admin):
        message_type, plaintext, _seq = await admin.channel.recv_admin()
        return apply_peer_event(admin.known_peers, message_type, plaintext)

    async def test_three_clients_learn_all_other_peers_and_leave(self):
        first = await self.connect_client()
        second = await self.connect_client()
        third = await self.connect_client()
        first_hs, first_admin, *_ = first
        second_hs, second_admin, *_ = second
        third_hs, third_admin, *_ = third

        # New clients learn all existing peers; existing clients learn the newcomer.
        self.assertEqual((await self.receive_peer_event(second_admin))[0], first_hs.client_id)
        self.assertEqual((await self.receive_peer_event(first_admin))[0], second_hs.client_id)
        self.assertEqual((await self.receive_peer_event(third_admin))[0], first_hs.client_id)
        self.assertEqual((await self.receive_peer_event(third_admin))[0], second_hs.client_id)
        self.assertEqual((await self.receive_peer_event(first_admin))[0], third_hs.client_id)
        self.assertEqual((await self.receive_peer_event(second_admin))[0], third_hs.client_id)

        self.assertEqual(set(first_admin.known_peers), {second_hs.client_id, third_hs.client_id})
        self.assertEqual(set(second_admin.known_peers), {first_hs.client_id, third_hs.client_id})
        self.assertEqual(set(third_admin.known_peers), {first_hs.client_id, second_hs.client_id})
        for handshake, admin, *_ in self.clients:
            self.assertNotIn(handshake.client_id, admin.known_peers)

        third[2].close()
        await third[3]
        self.assertEqual((await self.receive_peer_event(first_admin))[0], third_hs.client_id)
        self.assertEqual((await self.receive_peer_event(second_admin))[0], third_hs.client_id)
        self.assertNotIn(third_hs.client_id, first_admin.known_peers)
        self.assertNotIn(third_hs.client_id, second_admin.known_peers)

    async def test_simultaneous_arrivals_keep_confirmation_before_peer_info(self):
        first, second = await asyncio.gather(self.connect_client(), self.connect_client())
        first_hs, first_admin, *_ = first
        second_hs, second_admin, *_ = second
        self.assertEqual((await self.receive_peer_event(first_admin))[0], second_hs.client_id)
        self.assertEqual((await self.receive_peer_event(second_admin))[0], first_hs.client_id)
        self.assertEqual(set(first_admin.known_peers), {second_hs.client_id})
        self.assertEqual(set(second_admin.known_peers), {first_hs.client_id})

    async def asyncTearDown(self):
        for _handshake, _admin, writer, task in self.clients:
            writer.close()
        for _handshake, _admin, _writer, task in self.clients:
            if not task.done():
                await task


if __name__ == "__main__":
    unittest.main()
