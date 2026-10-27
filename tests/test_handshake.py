import asyncio
import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from client.client import HandshakeError, perform_client_handshake
from common.framing import recv_frame, send_frame
from common.protocol import HELLO, decode_hello
from server.handshake_server import create_server_hello, perform_server_handshake


class MemoryWriter:
    """In-memory counterpart for an asyncio StreamReader in handshake tests."""

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


def make_certificate(private_key, common_name: str) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
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


class HandshakeTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.certificate_der = make_certificate(cls.signing_key, "tp3-test-server")
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_certificate_der = make_certificate(cls.other_key, "other-tp3-server")

    def make_streams(self):
        client_reader = asyncio.StreamReader()
        server_reader = asyncio.StreamReader()
        client_writer = MemoryWriter(server_reader)
        server_writer = MemoryWriter(client_reader)
        return client_reader, client_writer, server_reader, server_writer

    async def test_valid_handshake_completes(self):
        client_reader, client_writer, server_reader, server_writer = self.make_streams()
        server_task = asyncio.create_task(
            perform_server_handshake(
                server_reader,
                server_writer,
                self.signing_key,
                self.certificate_der,
            )
        )

        client_session = await perform_client_handshake(
            client_reader,
            client_writer,
            self.certificate_der,
        )
        server_session = await server_task

        self.assertEqual(client_session.client_id, server_session.client_id)
        self.assertEqual(client_session.public_key, server_session.client_public_key)
        self.assertEqual(client_session.server_public_key, server_session.server_public_key)
        self.assertEqual(client_session.salt_srv, server_session.salt_srv)
        self.assertEqual(client_session.certificate_der, self.certificate_der)

    async def run_custom_responder(self, responder, pinned_certificate=None):
        client_reader, client_writer, server_reader, server_writer = self.make_streams()
        task = asyncio.create_task(responder(server_reader, server_writer))
        with self.assertRaises(HandshakeError):
            await perform_client_handshake(
                client_reader,
                client_writer,
                pinned_certificate or self.certificate_der,
            )
        await task

    async def test_different_pinned_certificate_is_rejected(self):
        async def responder(reader, writer):
            await perform_server_handshake(
                reader,
                writer,
                self.signing_key,
                self.certificate_der,
            )

        await self.run_custom_responder(responder, self.other_certificate_der)

    async def test_altered_signature_is_rejected(self):
        async def responder(reader, writer):
            message_type, payload = await recv_frame(reader)
            self.assertEqual(message_type, HELLO)
            client_id, client_public_key = decode_hello(payload)
            response, _ = create_server_hello(
                client_id,
                client_public_key,
                self.signing_key,
                self.certificate_der,
            )
            modified = bytearray(response)
            signature_length = int.from_bytes(modified[48:50], "big")
            self.assertGreater(signature_length, 0)
            modified[50] ^= 1
            await send_frame(writer, 0x02, bytes(modified))

        await self.run_custom_responder(responder)

    async def test_changed_signed_fields_are_rejected(self):
        async def verify_modified_field(field):
            async def responder(reader, writer):
                message_type, payload = await recv_frame(reader)
                self.assertEqual(message_type, HELLO)
                client_id, client_public_key = decode_hello(payload)
                signed_client_id = client_id
                if field == "client_id":
                    signed_client_id = bytes((client_id[0] ^ 1,)) + client_id[1:]
                response, _ = create_server_hello(
                    signed_client_id,
                    client_public_key,
                    self.signing_key,
                    self.certificate_der,
                )
                modified = bytearray(response)
                if field == "pk_S":
                    modified[0] ^= 1
                elif field == "salt":
                    modified[32] ^= 1
                await send_frame(writer, 0x02, bytes(modified))

            await self.run_custom_responder(responder)

        for field in ("pk_S", "salt", "client_id"):
            with self.subTest(field=field):
                await verify_modified_field(field)

    async def test_signature_from_another_rsa_key_is_rejected(self):
        async def responder(reader, writer):
            message_type, payload = await recv_frame(reader)
            self.assertEqual(message_type, HELLO)
            client_id, client_public_key = decode_hello(payload)
            response, _ = create_server_hello(
                client_id,
                client_public_key,
                self.other_key,
                self.certificate_der,
            )
            await send_frame(writer, 0x02, response)

        await self.run_custom_responder(responder)


if __name__ == "__main__":
    unittest.main()
