"""Offline tests — no network, no keys.

Covers the parts where a mistake would be silent: the ed25519 implementation, base58, and
the transaction body that decides which actions get signed.
"""
import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "near-keys.py"

spec = importlib.util.spec_from_file_location("near_keys", TOOL)
assert spec is not None and spec.loader is not None, "cannot load near-keys.py"
nk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nk)


class TestCrypto(unittest.TestCase):
    """RFC 8032 section 7.1 test vectors."""

    def test_vector_1_empty_message(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(nk.ed25519_public(sk), pk)
        self.assertEqual(nk.ed25519_sign(b"", sk, pk), sig)

    def test_vector_2_one_byte_message(self):
        sk = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pk = nk.ed25519_public(sk)
        sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertEqual(nk.ed25519_sign(b"\x72", sk, pk), sig)


class TestBase58(unittest.TestCase):

    def test_roundtrip(self):
        raw = bytes(range(32))
        self.assertEqual(nk.b58decode(nk.b58encode(raw)), raw)

    def test_leading_zeros(self):
        raw = b"\x00\x00" + bytes(range(30))
        encoded = nk.b58encode(raw)
        self.assertTrue(encoded.startswith("11"))
        self.assertEqual(nk.b58decode(encoded), raw)


class TestTransactionBody(unittest.TestCase):
    """The signed bytes must contain DeleteKey actions and nothing else."""

    def setUp(self):
        self.signer = "someone.near"
        self.pub = bytes(range(32))
        self.keys = ["ed25519:" + nk.b58encode(bytes([i] * 32)) for i in range(3)]
        self.body = nk.build_delete_keys_tx_body(
            self.signer, self.pub, self.keys, 223559754 * 1_000_000, bytes(32)
        )

    def _parse(self):
        b = self.body
        off = 0

        def read_string():
            nonlocal off
            n = int.from_bytes(b[off:off + 4], "little")
            off += 4
            v = b[off:off + n].decode()
            off += n
            return v

        signer = read_string()
        scheme = b[off]
        off += 33                                    # scheme byte + 32-byte key
        nonce = int.from_bytes(b[off:off + 8], "little")
        off += 8
        receiver = read_string()
        off += 32                                    # block hash
        n_actions = int.from_bytes(b[off:off + 4], "little")
        off += 4
        actions = []
        for _ in range(n_actions):
            actions.append(b[off])
            off += 34                                # variant + scheme + 32-byte key
        return signer, scheme, nonce, receiver, actions, off

    def test_only_delete_key_actions(self):
        signer, scheme, nonce, receiver, actions, off = self._parse()
        self.assertEqual(signer, self.signer)
        self.assertEqual(scheme, 0)                   # ED25519
        self.assertEqual(nonce, 223559754 * 1_000_000)
        self.assertEqual(receiver, self.signer)       # DeleteKey applies to the signer
        self.assertEqual(actions, [6, 6, 6])          # Action::DeleteKey
        self.assertEqual(off, len(self.body))         # nothing trailing

    def test_signature_appended_not_prefixed(self):
        signed = nk.build_delete_keys_tx(self.signer, b"\x01" * 32, self.pub,
                                         self.keys, 1, bytes(32))
        self.assertEqual(len(signed), len(self.body) + 65)   # 1 scheme byte + 64 sig


class TestSignerInput(unittest.TestCase):
    """Refuse seed phrases and non-ed25519 input with a message that points somewhere."""

    def test_seed_phrase_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            nk.parse_ed25519_secret("one two three four five six seven eight nine ten eleven twelve")
        self.assertIn("seed phrase", str(ctx.exception).lower())

    def test_secp256k1_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            nk.parse_ed25519_secret("secp256k1:abc")
        self.assertIn("ed25519", str(ctx.exception).lower())

    def test_key_file_roundtrip(self):
        seed = bytes([7] * 32)
        secret = "ed25519:" + nk.b58encode(seed + nk.ed25519_public(seed))
        got_seed, got_pub = nk.parse_ed25519_secret(secret)
        self.assertEqual(got_seed, seed)
        self.assertEqual(got_pub, nk.ed25519_public(seed))


class TestCli(unittest.TestCase):

    def test_help_runs(self):
        out = subprocess.run([sys.executable, str(TOOL), "--help"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("clean", out.stdout)

    def test_dry_run_is_the_default(self):
        out = subprocess.run([sys.executable, str(TOOL), "clean", "--help"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("actually sign and send", out.stdout)


if __name__ == "__main__":
    unittest.main()
