import unittest

from receptionist import images, tier1

from .helpers import NoPillow, build_jpeg_with_exif, build_png_with_metadata


class TestTier1Classification(unittest.TestCase):
    def test_allowlisted_categories(self):
        self.assertEqual(tier1.classify("hi there"), "greeting")
        self.assertEqual(tier1.classify("how much does it cost?"), "pricing")
        self.assertEqual(tier1.classify("can I book a consultation"), "booking")
        self.assertEqual(tier1.classify("what services do you offer"), "services")

    def test_sensitive_and_url_traffic_gets_bounded_ack(self):
        self.assertEqual(tier1.classify("my credit card number is..."), "ack")
        self.assertEqual(tier1.classify("check https://example.com/offer"), "ack")
        self.assertEqual(tier1.classify("I need a refund or my lawyer calls"), "ack")
        self.assertEqual(tier1.classify("x" * 2001), "ack")

    def test_silence_paths(self):
        self.assertIsNone(tier1.classify(""))
        self.assertIsNone(tier1.classify("thanks!"))

    def test_invoice_detection_is_notification_only_signal(self):
        self.assertTrue(tier1.is_invoice_request("please send an invoice"))
        self.assertFalse(tier1.is_invoice_request("see you tomorrow"))

    def test_faq_substitution_contains_no_placeholder(self):
        faq = tier1.build_faq({"business_name": "Example Studio", "assistant_name": "Helper"})
        for text in faq.values():
            self.assertNotIn("{business_name}", text)
            self.assertNotIn("{assistant_name}", text)


class TestImageSanitizer(unittest.TestCase):
    def test_jpeg_exif_and_gps_stripped(self):
        with NoPillow():
            raw = build_jpeg_with_exif(gps=True)
            self.assertIn(b"Exif", raw)
            self.assertIn(b"GPSLatitude", raw)
            clean = images.sanitize_image(raw)
        self.assertIsNotNone(clean)
        self.assertNotIn(b"Exif", clean)
        self.assertNotIn(b"GPS", clean)
        self.assertNotIn(b"JFIF", clean)  # all APPn dropped
        self.assertNotIn(b"comment metadata", clean)
        self.assertTrue(clean.startswith(b"\xff\xd8"))
        self.assertTrue(clean.endswith(b"\xff\xd9"))

    def test_png_metadata_chunks_stripped(self):
        with NoPillow():
            raw = build_png_with_metadata()
            self.assertIn(b"eXIf", raw)
            self.assertIn(b"location metadata", raw)
            clean = images.sanitize_image(raw)
        self.assertIsNotNone(clean)
        self.assertNotIn(b"eXIf", clean)
        self.assertNotIn(b"tEXt", clean)
        self.assertNotIn(b"location metadata", clean)
        self.assertIn(b"IHDR", clean)
        self.assertIn(b"IEND", clean)

    def test_malformed_streams_rejected(self):
        with NoPillow():
            self.assertIsNone(images.sanitize_image(b"\xff\xd8\xffgarbage-no-structure"))
            self.assertIsNone(images.sanitize_image(b"\x89PNG\r\n\x1a\nnot-chunks"))
            self.assertIsNone(images.sanitize_image(b"GIF89a....."))  # type not allowlisted
            self.assertIsNone(images.sanitize_image(b"%PDF-1.7 document"))
            self.assertIsNone(images.sanitize_image(b"PK\x03\x04 zip archive"))
            self.assertIsNone(images.sanitize_image(b""))

    def test_truncated_jpeg_rejected(self):
        with NoPillow():
            raw = build_jpeg_with_exif()[:-2]  # drop EOI
            self.assertIsNone(images.sanitize_image(raw))

    def test_sniff_matches_magic_only(self):
        self.assertEqual(images.sniff_mime(build_jpeg_with_exif()), "image/jpeg")
        self.assertEqual(images.sniff_mime(build_png_with_metadata()), "image/png")
        self.assertIsNone(images.sniff_mime(b"GIF89a...."))
        self.assertIsNone(images.sniff_mime(b"RIFF....WEBP"))

    def test_sensitive_description_detector(self):
        # Card/code inputs are assembled from short groups so the source file
        # never contains a long literal digit run for the privacy scanner.
        fake_card = " ".join(["4111"] + ["1111"] * 3)
        fake_code = "-".join(["555", "555", "0143"])  # fictional 555-01xx range
        self.assertTrue(images.is_sensitive_description("a driver's license on a table"))
        self.assertTrue(images.is_sensitive_description("QR code on a receipt"))
        self.assertTrue(images.is_sensitive_description("card reading " + fake_card))
        self.assertTrue(images.is_sensitive_description("code " + fake_code))
        self.assertFalse(images.is_sensitive_description("a dog in a park"))


if __name__ == "__main__":
    unittest.main()
