import unittest

from common.crypto import gen_x25519
from common.peer import derive_peer_session


class PeerKeyDerivationTests(unittest.TestCase):
    def test_two_clients_derive_opposite_matching_directional_keys(self):
        sk_a, pk_a = gen_x25519()
        sk_b, pk_b = gen_x25519()
        id_a, id_b = b"A" * 16, b"B" * 16
        salt_a, salt_b = b"a" * 16, b"b" * 16

        state_a = derive_peer_session(id_a, id_b, sk_a, pk_b, salt_a, salt_b)
        state_b = derive_peer_session(id_b, id_a, sk_b, pk_a, salt_b, salt_a)

        self.assertEqual(state_a.key_send, state_b.key_recv)
        self.assertEqual(state_a.key_recv, state_b.key_send)
        self.assertNotEqual(state_a.key_send, state_a.key_recv)
        self.assertNotEqual(state_b.key_send, state_b.key_recv)

    def test_distinct_pairs_get_distinct_keys_and_initialized_send_state(self):
        sk_a, _pk_a = gen_x25519()
        sk_b, pk_b = gen_x25519()
        _sk_c, pk_c = gen_x25519()
        id_a, id_b, id_c = b"A" * 16, b"B" * 16, b"C" * 16
        salt_a, salt_b, salt_c = b"a" * 16, b"b" * 16, b"c" * 16

        state_ab = derive_peer_session(id_a, id_b, sk_a, pk_b, salt_a, salt_b)
        state_ac = derive_peer_session(id_a, id_c, sk_a, pk_c, salt_a, salt_c)

        self.assertNotEqual(state_ab.key_send, state_ac.key_send)
        self.assertNotEqual(state_ab.key_recv, state_ac.key_recv)
        self.assertEqual((state_ab.seq_send, state_ab.seq_recv), (0, -1))
        self.assertEqual(len(state_ab.iv_base_send), 4)
        self.assertIsNone(state_ab.iv_base_recv)

    def test_self_peer_is_rejected(self):
        private_key, public_key = gen_x25519()
        with self.assertRaises(ValueError):
            derive_peer_session(
                b"A" * 16,
                b"A" * 16,
                private_key,
                public_key,
                b"a" * 16,
                b"a" * 16,
            )


if __name__ == "__main__":
    unittest.main()
