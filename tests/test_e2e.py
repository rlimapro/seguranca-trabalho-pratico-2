import asyncio
import unittest

from common.e2e import E2EProtocolError, MAX_PLAINTEXT, receive_e2e, send_e2e
from common.framing import recv_frame
from common.peer import derive_peer_session
from common.protocol import E2E, ERROR
from common.crypto import gen_x25519
from server.handshake_server import relay_e2e_frame


class MemoryWriter:
    def __init__(self, peer_reader):
        self.peer_reader = peer_reader

    def write(self, data):
        self.peer_reader.feed_data(data)

    async def drain(self):
        pass


class RecordingAdmin:
    def __init__(self):
        self.messages = []

    async def send_admin(self, message_type, plaintext):
        self.messages.append((message_type, plaintext))


class E2EMessageTests(unittest.IsolatedAsyncioTestCase):
    def make_peers(self):
        id_a, id_b = b"A" * 16, b"B" * 16
        sk_a, pk_a = gen_x25519()
        sk_b, pk_b = gen_x25519()
        salt_a, salt_b = b"a" * 16, b"b" * 16
        peer_a = derive_peer_session(id_a, id_b, sk_a, pk_b, salt_a, salt_b)
        peer_b = derive_peer_session(id_b, id_a, sk_b, pk_a, salt_b, salt_a)
        return id_a, id_b, peer_a, peer_b

    async def test_messages_roundtrip_both_directions_with_sequences(self):
        id_a, id_b, peer_a, peer_b = self.make_peers()
        a_to_server = asyncio.StreamReader()
        a_writer = MemoryWriter(a_to_server)
        b_to_server = asyncio.StreamReader()
        b_writer = MemoryWriter(b_to_server)

        for seq, message in enumerate((b"oi", b"segunda", b"terceira")):
            exact_payload = await send_e2e(a_writer, id_a, id_b, peer_a, message)
            frame_type, relayed_payload = await recv_frame(a_to_server)
            self.assertEqual(frame_type, E2E)
            self.assertEqual(relayed_payload, exact_payload)
            self.assertEqual(receive_e2e(id_b, {id_a: peer_b}, relayed_payload), (id_a, message))
            self.assertEqual(peer_b.seq_recv, seq)

        exact_payload = await send_e2e(b_writer, id_b, id_a, peer_b, b"volta")
        frame_type, relayed_payload = await recv_frame(b_to_server)
        self.assertEqual(frame_type, E2E)
        self.assertEqual(relayed_payload, exact_payload)
        self.assertEqual(receive_e2e(id_a, {id_b: peer_a}, relayed_payload), (id_b, b"volta"))

    async def test_plaintext_limit_is_checked_before_sequence_is_used(self):
        id_a, id_b, peer_a, _peer_b = self.make_peers()
        sink = asyncio.StreamReader()
        writer = MemoryWriter(sink)
        with self.assertRaises(E2EProtocolError):
            await send_e2e(writer, id_a, id_b, peer_a, b"x" * (MAX_PLAINTEXT + 1))
        self.assertEqual(peer_a.seq_send, 0)
        self.assertEqual(sink._buffer, b"")

    async def test_server_relays_opaque_payload_to_only_the_recipient(self):
        recipient_id = b"R" * 16
        sender_id = b"S" * 16
        recipient_reader = asyncio.StreamReader()
        other_reader = asyncio.StreamReader()
        recipient_writer = MemoryWriter(recipient_reader)
        other_writer = MemoryWriter(other_reader)
        sessions = {
            recipient_id: {"writer": recipient_writer},
            b"O" * 16: {"writer": other_writer},
        }
        payload = b"N" * 12 + sender_id + recipient_id + (9).to_bytes(8, "big") + b"C" * 24

        forwarded = await relay_e2e_frame(
            sender_id, payload, RecordingAdmin(), sessions, asyncio.Lock()
        )
        frame_type, received_payload = await recv_frame(recipient_reader)
        self.assertTrue(forwarded)
        self.assertEqual((frame_type, received_payload), (E2E, payload))
        self.assertEqual(other_reader._buffer, b"")

    async def test_missing_recipient_gets_an_encrypted_admin_error_request(self):
        sender_id = b"S" * 16
        admin = RecordingAdmin()
        payload = b"N" * 12 + sender_id + b"X" * 16 + (0).to_bytes(8, "big") + b"T" * 16
        forwarded = await relay_e2e_frame(
            sender_id, payload, admin, {}, asyncio.Lock()
        )
        self.assertFalse(forwarded)
        self.assertEqual(admin.messages, [(ERROR, "Destinatário indisponível".encode("utf-8"))])


if __name__ == "__main__":
    unittest.main()
