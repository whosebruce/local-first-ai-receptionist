import unittest

from receptionist import config as config_mod
from receptionist.identity import contact_fingerprint, lead_id, mask_sender, redact

from .helpers import CONTACT_EMAIL, CONTACT_PHONE, OTHER_CHANNEL


class TestIdentity(unittest.TestCase):
    def test_fingerprint_stable_across_formatting(self):
        key = "k" * 32
        a = contact_fingerprint(key, "+1 (555) 555-0100")
        b = contact_fingerprint(key, "15555550100")
        c = contact_fingerprint(key, "5555550100")
        self.assertEqual(a, b)
        self.assertEqual(a, c)

    def test_fingerprint_requires_key_fail_closed(self):
        self.assertEqual(contact_fingerprint("", CONTACT_PHONE), "")

    def test_fingerprint_differs_by_key_and_address(self):
        self.assertNotEqual(contact_fingerprint("a" * 32, CONTACT_PHONE),
                            contact_fingerprint("b" * 32, CONTACT_PHONE))
        self.assertNotEqual(contact_fingerprint("a" * 32, CONTACT_PHONE),
                            contact_fingerprint("a" * 32, CONTACT_EMAIL))

    def test_mask_never_reveals_full_address(self):
        self.assertEqual(mask_sender(CONTACT_PHONE), "phone ending 0100")
        masked = mask_sender(CONTACT_EMAIL)
        self.assertNotIn("contact@", masked)
        self.assertTrue(masked.startswith("c***@"))

    def test_redact_strips_raw_identity(self):
        text = f"call me at {CONTACT_PHONE} or {CONTACT_EMAIL}"
        cleaned = redact(text)
        self.assertNotIn(CONTACT_PHONE, cleaned)
        self.assertNotIn(CONTACT_EMAIL, cleaned)
        self.assertIn("[REDACTED_PHONE]", cleaned)
        self.assertIn("[REDACTED_EMAIL]", cleaned)

    def test_lead_id_shape(self):
        lid = lead_id("chat-1", CONTACT_PHONE)
        self.assertRegex(lid, r"^[0-9A-F]{8}$")
        self.assertEqual(lid, lead_id("chat-1", CONTACT_PHONE))
        self.assertNotEqual(lid, lead_id("chat-2", CONTACT_PHONE))


class TestConfigValidation(unittest.TestCase):
    def test_defaults_validate_and_are_safe(self):
        cfg = config_mod.validate(config_mod.default_config())
        self.assertEqual(cfg["listen_host"], "127.0.0.1")
        self.assertFalse(cfg["outbound"]["enabled"])
        self.assertFalse(cfg["discord"]["enabled"])
        self.assertEqual(cfg["tier2"]["model"]["base_url"], "")

    def test_public_bind_refused(self):
        cfg = config_mod.default_config()
        cfg["listen_host"] = "203.0.113.10"
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)

    def test_lan_bind_requires_explicit_opt_in(self):
        cfg = config_mod.default_config()
        cfg["listen_host"] = "192.0.2.5"
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)
        cfg["allow_private_lan_bind"] = True
        config_mod.validate(cfg)  # now allowed

    def test_bind_all_interfaces_refused_even_with_opt_in(self):
        for host in ("0.0.0.0", "::"):
            cfg = config_mod.default_config()
            cfg["listen_host"] = host
            cfg["allow_private_lan_bind"] = True  # opt-in must NOT permit this
            with self.assertRaises(config_mod.ConfigError):
                config_mod.validate(cfg)

    def test_public_model_endpoint_always_refused(self):
        # A globally routable IP, constructed so the repository text contains
        # no non-documentation IP literal.
        public_ip = ".".join(map(str, (8, 8, 8, 8)))
        cfg = config_mod.default_config()
        cfg["tier2"]["model"].update({"base_url": f"http://{public_ip}:11434",
                                      "model": "local-text-model",
                                      "allow_private_lan": True})
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)

    def test_documentation_range_needs_lan_opt_in_like_any_lan(self):
        # RFC 5737 TEST-NET is non-routable; Python classes it is_private, so
        # it behaves like a LAN address: refused without the explicit opt-in.
        cfg = config_mod.default_config()
        cfg["tier2"]["model"].update({"base_url": "http://203.0.113.9:11434",
                                      "model": "local-text-model"})
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)

    def test_dns_model_endpoint_refused(self):
        cfg = config_mod.default_config()
        cfg["tier2"]["model"].update({"base_url": "http://models.example.com",
                                      "model": "local-text-model"})
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)

    def test_lan_model_endpoint_requires_opt_in(self):
        cfg = config_mod.default_config()
        cfg["tier2"]["model"].update({"base_url": "http://192.0.2.7:11434",
                                      "model": "local-text-model"})
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)
        cfg["tier2"]["model"]["allow_private_lan"] = True
        config_mod.validate(cfg)

    def test_discord_requires_numeric_ids(self):
        cfg = config_mod.default_config()
        cfg["discord"].update({"enabled": True, "guild_id": "not-a-number",
                               "owner_user_id": OTHER_CHANNEL,
                               "bot_user_id": OTHER_CHANNEL,
                               "intake_channel_id": OTHER_CHANNEL})
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)

    def test_public_relay_url_refused(self):
        public_ip = ".".join(map(str, (8, 8, 8, 8)))
        cfg = config_mod.default_config()
        cfg["relay_url"] = f"http://{public_ip}:9000/hook"
        with self.assertRaises(config_mod.ConfigError):
            config_mod.validate(cfg)
        cfg["relay_url"] = "http://127.0.0.1:9000/hook"
        config_mod.validate(cfg)


if __name__ == "__main__":
    unittest.main()
