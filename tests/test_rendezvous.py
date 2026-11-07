import asyncio
import datetime
import unittest
import uuid
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from client.client import (
    apply_peer_event,
    establish_admin_channel,
    perform_client_handshake,
    send_to_peer,
)
from common.e2e import E2EProtocolError, MAX_PLAINTEXT, receive_e2e, send_e2e
from common.framing import recv_frame, send_frame
from common.protocol import E2E, ERROR
from server.handshake_server import ConnectionLimiter, handle_handshake_client


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

    async def connect_client(self, client_id=None, limiter=None):
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
                limiter,
            )
        )
        if client_id is None:
            handshake = await perform_client_handshake(client_reader, client_writer, self.certificate)
        else:
            with patch("client.client.uuid.uuid4", return_value=uuid.UUID(bytes=client_id)):
                handshake = await perform_client_handshake(client_reader, client_writer, self.certificate)
        admin = await establish_admin_channel(handshake)
        connection = (handshake, admin, client_writer, task)
        self.clients.append(connection)
        return connection

    async def receive_peer_event(self, handshake, admin):
        message_type, plaintext, _seq = await admin.channel.recv_admin()
        return apply_peer_event(
            handshake, admin.known_peers, admin.peers, message_type, plaintext
        )

    async def test_three_clients_learn_all_other_peers_and_leave(self):
        first = await self.connect_client()
        second = await self.connect_client()
        third = await self.connect_client()
        first_hs, first_admin, *_ = first
        second_hs, second_admin, *_ = second
        third_hs, third_admin, *_ = third

        # New clients learn all existing peers; existing clients learn the newcomer.
        self.assertEqual((await self.receive_peer_event(second_hs, second_admin))[0], first_hs.client_id)
        self.assertEqual((await self.receive_peer_event(first_hs, first_admin))[0], second_hs.client_id)
        self.assertEqual((await self.receive_peer_event(third_hs, third_admin))[0], first_hs.client_id)
        self.assertEqual((await self.receive_peer_event(third_hs, third_admin))[0], second_hs.client_id)
        self.assertEqual((await self.receive_peer_event(first_hs, first_admin))[0], third_hs.client_id)
        self.assertEqual((await self.receive_peer_event(second_hs, second_admin))[0], third_hs.client_id)

        self.assertEqual(set(first_admin.known_peers), {second_hs.client_id, third_hs.client_id})
        self.assertEqual(set(second_admin.known_peers), {first_hs.client_id, third_hs.client_id})
        self.assertEqual(set(third_admin.known_peers), {first_hs.client_id, second_hs.client_id})
        self.assertEqual(
            first_admin.peers[second_hs.client_id].key_send,
            second_admin.peers[first_hs.client_id].key_recv,
        )
        self.assertEqual(
            first_admin.peers[second_hs.client_id].key_recv,
            second_admin.peers[first_hs.client_id].key_send,
        )
        for handshake, admin, *_ in self.clients:
            self.assertNotIn(handshake.client_id, admin.known_peers)
            self.assertNotIn(handshake.client_id, admin.peers)

        first_peer = first_admin.peers[second_hs.client_id]
        resolved_peer, sent_seq, sent_payload = await send_to_peer(
            first_hs,
            first_admin,
            f"/to {second_hs.client_id.hex()[:8]} oi, Bruno",
        )
        self.assertEqual((resolved_peer, sent_seq), (second_hs.client_id, 0))
        frame_type, received_payload = await recv_frame(second_hs.reader)
        self.assertEqual(frame_type, E2E)
        self.assertEqual(received_payload, sent_payload)  # relay preserves the bytes
        self.assertEqual(
            receive_e2e(second_hs.client_id, second_admin.peers, received_payload),
            (first_hs.client_id, "oi, Bruno".encode("utf-8")),
        )

        second_peer = second_admin.peers[first_hs.client_id]
        for message in (b"resposta", b"segunda mensagem"):
            await send_e2e(
                second_hs.writer,
                second_hs.client_id,
                first_hs.client_id,
                second_peer,
                message,
            )
            frame_type, received_payload = await recv_frame(first_hs.reader)
            self.assertEqual(frame_type, E2E)
            self.assertEqual(
                receive_e2e(first_hs.client_id, first_admin.peers, received_payload),
                (second_hs.client_id, message),
            )
        self.assertEqual(third_hs.reader._buffer, b"")

        missing_recipient = b"Z" * 16
        opaque_payload = (
            b"N" * 12
            + first_hs.client_id
            + missing_recipient
            + (0).to_bytes(8, "big")
            + b"T" * 16
        )
        await send_frame(first_hs.writer, E2E, opaque_payload)
        message_type, admin_payload = await recv_frame(first_hs.reader)
        self.assertEqual(message_type, ERROR)
        _, error_text, _ = first_admin.channel.decode_admin_frame(message_type, admin_payload)
        self.assertEqual(error_text.decode("utf-8"), "Destinatário indisponível")

        with self.assertRaises(E2EProtocolError):
            await send_e2e(
                first_hs.writer,
                first_hs.client_id,
                second_hs.client_id,
                first_peer,
                b"x" * (MAX_PLAINTEXT + 1),
            )
        self.assertEqual(first_peer.seq_send, 1)

        third[2].close()
        await third[3]
        self.assertEqual((await self.receive_peer_event(first_hs, first_admin))[0], third_hs.client_id)
        self.assertEqual((await self.receive_peer_event(second_hs, second_admin))[0], third_hs.client_id)
        self.assertNotIn(third_hs.client_id, first_admin.known_peers)
        self.assertNotIn(third_hs.client_id, second_admin.known_peers)
        self.assertNotIn(third_hs.client_id, first_admin.peers)
        self.assertNotIn(third_hs.client_id, second_admin.peers)

    async def test_simultaneous_arrivals_keep_confirmation_before_peer_info(self):
        first, second = await asyncio.gather(self.connect_client(), self.connect_client())
        first_hs, first_admin, *_ = first
        second_hs, second_admin, *_ = second
        self.assertEqual((await self.receive_peer_event(first_hs, first_admin))[0], second_hs.client_id)
        self.assertEqual((await self.receive_peer_event(second_hs, second_admin))[0], first_hs.client_id)
        self.assertEqual(set(first_admin.known_peers), {second_hs.client_id})
        self.assertEqual(set(second_admin.known_peers), {first_hs.client_id})

    async def test_reconnect_replaces_session_and_peers_get_fresh_material(self):
        old_a = await self.connect_client()
        b = await self.connect_client()
        old_hs, old_admin, old_writer, old_task = old_a
        b_hs, b_admin, *_ = b
        await self.receive_peer_event(old_hs, old_admin)
        await self.receive_peer_event(b_hs, b_admin)
        old_peer_key = b_admin.peers[old_hs.client_id].key_send

        new_a = await self.connect_client(client_id=old_hs.client_id)
        new_hs, new_admin, _new_writer, _new_task = new_a
        replacement_notice = await self.receive_peer_event(b_hs, b_admin)
        await self.receive_peer_event(new_hs, new_admin)

        self.assertEqual(replacement_notice[0], old_hs.client_id)
        self.assertNotEqual(old_hs.public_key, new_hs.public_key)
        self.assertNotEqual(old_hs.salt_srv, new_hs.salt_srv)
        self.assertNotEqual(old_peer_key, b_admin.peers[old_hs.client_id].key_send)
        self.assertEqual(b_admin.known_peers[old_hs.client_id], (new_hs.public_key, new_hs.salt_srv))
        self.assertEqual(self.sessions[old_hs.client_id]["public_key"], new_hs.public_key)
        self.assertEqual(self.sessions[old_hs.client_id]["salt"], new_hs.salt_srv)
        old_writer.close()
        await old_task

    async def test_connection_limit_rejects_excess_connection_safely(self):
        limiter = ConnectionLimiter(1)
        self.assertTrue(await limiter.acquire())
        server_reader = asyncio.StreamReader()
        client_reader = asyncio.StreamReader()
        writer = MemoryWriter(client_reader)
        await handle_handshake_client(
            server_reader,
            writer,
            self.signing_key,
            self.certificate,
            self.sessions,
            self.lock,
            limiter,
        )
        self.assertTrue(writer.closed)
        self.assertEqual(limiter.active, 1)
        await limiter.release()
        self.assertEqual(limiter.active, 0)

    async def test_accepted_connection_releases_limiter_on_disconnect(self):
        limiter = ConnectionLimiter(1)
        client = await self.connect_client(limiter=limiter)
        self.assertEqual(limiter.active, 1)

        client[2].close()
        await client[3]

        self.assertEqual(limiter.active, 0)

    async def test_clean_eof_before_hello_is_not_logged_as_rejected_handshake(self):
        server_reader = asyncio.StreamReader()
        server_reader.feed_eof()
        writer = MemoryWriter(asyncio.StreamReader())

        with self.assertLogs("tp3.handshake_server", level="INFO") as captured:
            await handle_handshake_client(
                server_reader,
                writer,
                self.signing_key,
                self.certificate,
                self.sessions,
                self.lock,
            )

        log_text = "\n".join(captured.output)
        self.assertIn("conexão encerrada antes do HELLO", log_text)
        self.assertNotIn("handshake rejeitado", log_text)

    async def test_server_logs_do_not_contain_peer_key_or_salt(self):
        with self.assertLogs("tp3.handshake_server", level="INFO") as captured:
            client = await self.connect_client()
            handshake = client[0]
            client[2].close()
            await client[3]
        log_text = "\n".join(captured.output)
        self.assertIn(handshake.client_id.hex(), log_text)
        self.assertIn("desconexão:", log_text)
        self.assertNotIn("handshake rejeitado", log_text)
        self.assertNotIn(handshake.public_key.hex(), log_text)
        self.assertNotIn(handshake.salt_srv.hex(), log_text)

    async def asyncTearDown(self):
        for _handshake, _admin, writer, task in self.clients:
            writer.close()
        for _handshake, _admin, _writer, task in self.clients:
            if not task.done():
                await task


if __name__ == "__main__":
    unittest.main()
