import itertools
import unittest

from intake import fingerprint as fp


class FingerprintTest(unittest.TestCase):
    REPORT = "path traversal in src/mod137.py via parameter path"

    def test_equal_reports_with_different_nonces_differ(self):
        a = fp.fingerprint(self.REPORT, b"\x00" * 16)
        b = fp.fingerprint(self.REPORT, b"\x01" + b"\x00" * 15)
        self.assertNotEqual(a, b)

    def test_fresh_nonces_differ_for_equal_reports(self):
        r1, r2 = fp.receipt(self.REPORT, "security"), fp.receipt(self.REPORT, "security")
        self.assertNotEqual(r1["nonce"], r2["nonce"])
        self.assertNotEqual(r1["fingerprint"], r2["fingerprint"])

    def test_is_sha256_of_nonce_then_report(self):
        import hashlib
        nonce = bytes(range(16))
        want = hashlib.sha256(nonce + self.REPORT.encode("utf-8")).hexdigest()
        self.assertEqual(fp.fingerprint(self.REPORT, nonce), want)

    def test_submitter_verifies_with_nonce(self):
        r = fp.receipt(self.REPORT, "bug")
        nonce = bytes.fromhex(r["nonce"])
        self.assertTrue(fp.verify(self.REPORT, nonce, r["fingerprint"]))
        self.assertFalse(fp.verify(self.REPORT + ".", nonce, r["fingerprint"]))

    def test_short_report_not_recovered_by_guessing_without_nonce(self):
        kinds = ["path traversal", "SQL injection", "XSS", "SSRF", "open redirect"]
        files = [f"src/mod{i}.py" for i in range(200)]
        params = ["path", "id", "url", "q", "next"]
        r = fp.receipt(self.REPORT, "security")
        import hashlib
        guesses = (f"{k} in {f} via parameter {p}" for k, f, p in itertools.product(kinds, files, params))
        hits = [g for g in guesses if hashlib.sha256(g.encode()).hexdigest() == r["fingerprint"]]
        self.assertEqual(hits, [])

    def test_every_kind_uses_the_same_scheme(self):
        for kind in fp.KINDS:
            r = fp.receipt(self.REPORT, kind)
            self.assertEqual(r["scheme"], fp.SCHEME)
            self.assertTrue(fp.verify(self.REPORT, bytes.fromhex(r["nonce"]), r["fingerprint"]))

    def test_rejects_unknown_kind_and_bad_nonce(self):
        with self.assertRaises(ValueError):
            fp.receipt(self.REPORT, "feature-request")
        with self.assertRaises(ValueError):
            fp.fingerprint(self.REPORT, b"short")


if __name__ == "__main__":
    unittest.main()
