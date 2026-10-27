import hashlib
import unittest

from cryptography.exceptions import InvalidTag

from common.crypto import (
    aes_decrypt,
    aes_encrypt,
    build_aad_admin,
    build_aad_e2e,
    build_nonce,
    ecdh,
    fingerprint,
    gen_x25519,
    hkdf_extract_expand,
)


class CryptoTests(unittest.TestCase):
    def test_x25519_shared_secret_matches(self):
        sk_a, pk_a = gen_x25519()
        sk_b, pk_b = gen_x25519()

        self.assertEqual(ecdh(sk_a, pk_b), ecdh(sk_b, pk_a))
        self.assertEqual(len(pk_a), 32)
        self.assertEqual(len(pk_b), 32)

    def test_aes_gcm_roundtrip_and_authentication_failures(self):
        key = bytes(range(16))
        nonce = build_nonce(b"iv00", 12)
        aad = build_aad_e2e(b"A" * 16, b"B" * 16, 12)
        plaintext = b"mensagem de teste"
        ciphertext = aes_encrypt(key, nonce, aad, plaintext)

        self.assertEqual(aes_decrypt(key, nonce, aad, ciphertext), plaintext)

        changed_ciphertext = bytes((ciphertext[0] ^ 1,)) + ciphertext[1:]
        changed_nonce = bytes((nonce[0] ^ 1,)) + nonce[1:]
        changed_aad = bytes((aad[0] ^ 1,)) + aad[1:]
        for altered_nonce, altered_aad, altered_ciphertext in (
            (nonce, aad, changed_ciphertext),
            (changed_nonce, aad, ciphertext),
            (nonce, changed_aad, ciphertext),
        ):
            with self.subTest(altered=(altered_nonce, altered_aad, altered_ciphertext)):
                with self.assertRaises(InvalidTag):
                    aes_decrypt(key, altered_nonce, altered_aad, altered_ciphertext)

    def test_directional_hkdf_keys_are_distinct(self):
        salt = b"s" * 16
        shared_secret = b"z" * 32

        key_a2b = hkdf_extract_expand(salt, shared_secret, b"A2B")
        key_b2a = hkdf_extract_expand(salt, shared_secret, b"B2A")

        self.assertEqual(len(key_a2b), 16)
        self.assertEqual(len(key_b2a), 16)
        self.assertNotEqual(key_a2b, key_b2a)

    def test_nonce_aad_and_fingerprint_formats(self):
        self.assertEqual(build_nonce(b"base", 1), b"base" + (1).to_bytes(8, "big"))
        self.assertEqual(build_nonce(1, 2), b"\x00\x00\x00\x01" + (2).to_bytes(8, "big"))
        self.assertEqual(len(build_nonce(b"base", 0)), 12)
        self.assertEqual(build_aad_e2e(b"A" * 16, b"B" * 16, 7), b"A" * 16 + b"B" * 16 + (7).to_bytes(8, "big"))
        self.assertEqual(build_aad_admin(6, 3), b"\x06" + (3).to_bytes(8, "big"))

        public_key = b"p" * 32
        expected = hashlib.sha256(public_key).digest()[:8].hex()
        self.assertEqual(fingerprint(public_key), expected)

    def test_aes_128_and_nonce_lengths_are_enforced(self):
        with self.assertRaises(ValueError):
            aes_encrypt(b"k" * 15, b"n" * 12, b"", b"x")
        with self.assertRaises(ValueError):
            aes_encrypt(b"k" * 16, b"n" * 11, b"", b"x")


if __name__ == "__main__":
    unittest.main()
