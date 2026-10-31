import asyncio
import struct
import unittest

from cryptography.exceptions import InvalidTag

from common.crypto import aes_decrypt, aes_encrypt, build_aad_e2e, gen_x25519
from common.e2e import (
    E2EAuthenticationError,
    E2EReplayError,
    receive_e2e,
    send_e2e,
)
from common.framing import FrameError, MAX_FRAME, recv_frame
from common.peer import derive_peer_session
from common.protocol import E2E


class MemoryWriter:
    def __init__(self, reader):
        self.reader = reader

    def write(self, data):
        self.reader.feed_data(data)

    async def drain(self):
        pass


class AttackRejectionTests(unittest.IsolatedAsyncioTestCase):
    def make_pair(self):
        id_a, id_b = b"A" * 16, b"B" * 16
        sk_a, pk_a = gen_x25519()
        sk_b, pk_b = gen_x25519()
        salt_a, salt_b = b"a" * 16, b"b" * 16
        peer_a = derive_peer_session(id_a, id_b, sk_a, pk_b, salt_a, salt_b)
        peer_b = derive_peer_session(id_b, id_a, sk_b, pk_a, salt_b, salt_a)
        return id_a, id_b, peer_a, peer_b

    async def read_payload(self, reader):
        frame_type, payload = await recv_frame(reader)
        self.assertEqual(frame_type, E2E)
        return payload

    async def test_normal_message_and_recovery_after_bitflip(self):
        id_a, id_b, peer_a, peer_b = self.make_pair()
        wire = asyncio.StreamReader()
        writer = MemoryWriter(wire)

        await send_e2e(writer, id_a, id_b, peer_a, b"adulterada", attack="bitflip")
        corrupted = await self.read_payload(wire)
        with self.assertRaises(E2EAuthenticationError):
            receive_e2e(id_b, {id_a: peer_b}, corrupted)
        self.assertEqual(peer_b.seq_recv, -1)

        valid_message = "mensagem legítima".encode()
        await send_e2e(writer, id_a, id_b, peer_a, valid_message)
        valid = await self.read_payload(wire)
        self.assertEqual(receive_e2e(id_b, {id_a: peer_b}, valid), (id_a, valid_message))

    async def test_replay_is_rejected_without_blocking_later_messages(self):
        id_a, id_b, peer_a, peer_b = self.make_pair()
        wire = asyncio.StreamReader()
        writer = MemoryWriter(wire)

        await send_e2e(writer, id_a, id_b, peer_a, b"primeira", attack="replay")
        original = await self.read_payload(wire)
        duplicate = await self.read_payload(wire)
        self.assertEqual(receive_e2e(id_b, {id_a: peer_b}, original), (id_a, b"primeira"))
        with self.assertRaises(E2EReplayError):
            receive_e2e(id_b, {id_a: peer_b}, duplicate)

        await send_e2e(writer, id_a, id_b, peer_a, b"depois")
        later = await self.read_payload(wire)
        self.assertEqual(receive_e2e(id_b, {id_a: peer_b}, later), (id_a, b"depois"))

    async def test_address_fields_are_authenticated_by_aad(self):
        id_a, id_b, peer_a, _peer_b = self.make_pair()
        nonce = b"n" * 12
        seq = 7
        ciphertext = aes_encrypt(peer_a.key_send, nonce, build_aad_e2e(id_a, id_b, seq), b"oi")
        for sender, recipient in ((b"X" * 16, id_b), (id_a, b"Y" * 16)):
            with self.subTest(sender=sender[:1], recipient=recipient[:1]):
                with self.assertRaises(InvalidTag):
                    aes_decrypt(
                        peer_a.key_send,
                        nonce,
                        build_aad_e2e(sender, recipient, seq),
                        ciphertext,
                    )

    async def test_invalid_oversized_and_truncated_frames_are_rejected(self):
        oversized = asyncio.StreamReader()
        oversized.feed_data(struct.pack("!I", MAX_FRAME + 1))
        oversized.feed_eof()
        with self.assertRaises(FrameError):
            await recv_frame(oversized)

        truncated = asyncio.StreamReader()
        truncated.feed_data(struct.pack("!I", 5) + b"\x05ab")
        truncated.feed_eof()
        with self.assertRaises(asyncio.IncompleteReadError):
            await recv_frame(truncated)


if __name__ == "__main__":
    unittest.main()
