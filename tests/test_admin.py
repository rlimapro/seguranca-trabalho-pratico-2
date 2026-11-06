import asyncio
import datetime
import unittest

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from client.client import establish_admin_channel, perform_client_handshake
from common.admin import AdminChannel, AdminReplayError
from common.protocol import ERROR, REGISTERED
from server.handshake_server import handle_handshake_client


class MemoryWriter:
    def __init__(self, peer_reader):
        self.peer_reader = peer_reader
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)
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


def make_certificate(private_key):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "tp3-admin-test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class AdminChannelTests(unittest.IsolatedAsyncioTestCase):
    def make_channels(self):
        client_reader = asyncio.StreamReader()
        server_reader = asyncio.StreamReader()
        client_writer = MemoryWriter(server_reader)
        server_writer = MemoryWriter(client_reader)
        c2s = b"C" * 16
        s2c = b"S" * 16
        client = AdminChannel(
            client_reader,
            client_writer,
            key_send=c2s,
            key_recv=s2c,
            direction_send=0,
            direction_recv=1,
        )
        server = AdminChannel(
            server_reader,
            server_writer,
            key_send=s2c,
            key_recv=c2s,
            direction_send=1,
            direction_recv=0,
        )
        return client, server, client_reader, client_writer, server_reader, server_writer

    async def test_initial_counters_and_admin_roundtrip(self):
        client, server, *_ = self.make_channels()
        self.assertEqual((client.seq_send, client.seq_recv), (0, -1))
        self.assertEqual((server.seq_send, server.seq_recv), (0, -1))

        used_seq = await server.send_admin(REGISTERED, b"Registro confirmado")
        message_type, plaintext, received_seq = await client.recv_admin()

        self.assertEqual(used_seq, 0)
        self.assertEqual((message_type, plaintext, received_seq), (REGISTERED, b"Registro confirmado", 0))
        self.assertEqual((server.seq_send, server.seq_recv), (1, -1))
        self.assertEqual((client.seq_send, client.seq_recv), (0, 0))

    async def test_replayed_admin_frame_is_rejected(self):
        _client, server, client_reader, _client_writer, _server_reader, server_writer = self.make_channels()
        await server.send_admin(ERROR, b"aviso")
        old_frame = bytes(server_writer.data)
        unused_peer_reader = asyncio.StreamReader()
        client_receiver = AdminChannel(
            client_reader,
            MemoryWriter(unused_peer_reader),
            key_send=b"C" * 16,
            key_recv=b"S" * 16,
            direction_send=0,
            direction_recv=1,
        )

        self.assertEqual((await client_receiver.recv_admin())[2], 0)
        client_reader.feed_data(old_frame)
        with self.assertRaises(AdminReplayError):
            await client_receiver.recv_admin()
        self.assertEqual(client_receiver.seq_recv, 0)

    async def test_bitflip_does_not_advance_receive_counter(self):
        _client, server, _client_reader, _client_writer, _server_reader, server_writer = self.make_channels()
        await server.send_admin(ERROR, b"aviso autenticado")
        valid_frame = bytes(server_writer.data)
        altered_frame = bytearray(valid_frame)
        altered_frame[13] ^= 1  # first ciphertext byte; prefix + type + seq precede it
        client_reader = asyncio.StreamReader()
        client_reader.feed_data(bytes(altered_frame))
        client_receiver = AdminChannel(
            client_reader,
            MemoryWriter(asyncio.StreamReader()),
            key_send=b"C" * 16,
            key_recv=b"S" * 16,
            direction_send=0,
            direction_recv=1,
        )
        with self.assertRaises(InvalidTag):
            await client_receiver.recv_admin()
        self.assertEqual(client_receiver.seq_recv, -1)

        client_reader.feed_data(valid_frame)
        self.assertEqual((await client_receiver.recv_admin())[1:], (b"aviso autenticado", 0))
        self.assertEqual(client_receiver.seq_recv, 0)

    async def test_server_registers_session_and_sends_encrypted_confirmation(self):
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate_der = make_certificate(signing_key)
        client_reader = asyncio.StreamReader()
        server_reader = asyncio.StreamReader()
        client_writer = MemoryWriter(server_reader)
        server_writer = MemoryWriter(client_reader)
        sessions = {}
        lock = asyncio.Lock()

        server_task = asyncio.create_task(
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

        self.assertEqual(admin.confirmation, b"Registro confirmado")
        self.assertEqual(admin.channel.seq_recv, 0)
        session = sessions[handshake.client_id]
        self.assertEqual(session["public_key"], handshake.public_key)
        self.assertEqual(session["salt"], handshake.salt_srv)
        self.assertEqual(session["seq_send"], 1)  # seq 0 carried the confirmation
        self.assertEqual(session["seq_recv"], -1)
        self.assertEqual(session["admin"].seq_send, 1)

        client_writer.close()
        await server_task
        self.assertNotIn(handshake.client_id, sessions)


if __name__ == "__main__":
    unittest.main()
