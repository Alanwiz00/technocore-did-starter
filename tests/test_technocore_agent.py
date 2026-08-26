import json
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.request import Request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import technocore_agent as agent
import technocore_runner as runner


class IdentityTests(unittest.TestCase):
    def test_identity_round_trip_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.pem"
            did = agent.create_identity(path, "five-calm-random-words")
            loaded = agent.load_identity(
                path, b"five-calm-random-words", allow_prompt=False
            )
            self.assertEqual(agent.did_from_private_key(loaded), did)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_identity_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.pem"
            path.write_bytes(b"x" * (agent.MAX_IDENTITY_BYTES + 1))
            with self.assertRaisesRegex(agent.IdentityError, "safety limit"):
                agent.load_identity(path, b"irrelevant", allow_prompt=False)

    @unittest.skipIf(not hasattr(__import__("os"), "mkfifo"), "FIFO unavailable")
    def test_identity_reader_rejects_non_regular_files(self):
        import os

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.pipe"
            os.mkfifo(path)
            with self.assertRaisesRegex(agent.IdentityError, "not a regular file"):
                agent.load_identity(path, b"irrelevant", allow_prompt=False)

    def test_import_hex_seed_preserves_expected_did(self):
        seed = bytes(range(32))
        source = Ed25519PrivateKey.from_private_bytes(seed)
        expected_did = agent.did_from_private_key(source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "imported.pem"
            actual_did = agent.import_seed_identity(
                path, seed.hex(), "five-calm-random-words", expected_did
            )
            loaded = agent.load_identity(
                path, b"five-calm-random-words", allow_prompt=False
            )
            self.assertEqual(actual_did, expected_did)
            self.assertEqual(agent.did_from_private_key(loaded), expected_did)

    def test_import_rejects_did_mismatch_without_writing(self):
        seed = bytes(range(32))
        other_did = agent.did_from_private_key(Ed25519PrivateKey.generate())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "imported.pem"
            with self.assertRaisesRegex(agent.IdentityError, "different DID"):
                agent.import_seed_identity(
                    path, seed.hex(), "five-calm-random-words", other_did
                )
            self.assertFalse(path.exists())

    def test_import_rejects_non_hex_seed(self):
        with self.assertRaisesRegex(agent.IdentityError, "64 hexadecimal"):
            agent.import_seed_identity(
                Path("unused.pem"), "z" * 64, "five-calm-random-words", "unused"
            )


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()

    def test_message_signature_round_trip(self):
        text, payload = agent.message_payload("lobby", "123", "hello\nworld")
        signature = agent.sign_bytes(self.key, payload)
        agent.verify_bytes(agent.did_from_private_key(self.key), signature, payload)
        self.assertEqual(text, "hello world")

    def test_proof_is_strict_and_canonical(self):
        proof = agent.create_contribution_proof(
            self.key, "https://example.com/repository", "a" * 40
        )
        agent.verify_contribution_proof(proof)
        with self.assertRaisesRegex(agent.ProtocolError, "exactly"):
            agent.verify_contribution_proof({**proof, "note": "not signed"})
        uppercase = {**proof, "commit": "A" * 40}
        with self.assertRaisesRegex(agent.ProtocolError, "lowercase"):
            agent.verify_contribution_proof(uppercase)

    def test_malformed_unicode_urls_are_controlled_errors(self):
        with self.assertRaises(agent.ProtocolError):
            agent.validate_base_url("https://\ud800")
        with self.assertRaises(agent.ProtocolError):
            agent.contribution_payload("https://\ud800/repo", "a" * 40)

    def test_room_messages_are_validated(self):
        response = {
            "room": "lobby",
            "count": 1,
            "last_seq": 1,
            "messages": [{"seq": 1, "from": "Not Valid", "text": "hello"}],
        }
        with self.assertRaisesRegex(agent.NetworkError, "sender nickname"):
            agent.validate_room_response(response, "lobby")

    def test_unsigned_human_message_is_accepted(self):
        response = {
            "room": "chat",
            "count": 1,
            "last_seq": 84,
            "messages": [{"seq": 84, "from": "human", "text": "hello"}],
        }
        agent.validate_room_response(response, "chat")

    def test_signed_message_requires_nonce(self):
        response = {
            "room": "chat",
            "count": 1,
            "last_seq": 1,
            "messages": [
                {
                    "seq": 1,
                    "from": agent.did_from_private_key(self.key),
                    "text": "hello",
                }
            ],
        }
        with self.assertRaisesRegex(agent.NetworkError, "DID or nonce"):
            agent.validate_room_response(response, "chat")


class NetworkTests(unittest.TestCase):
    def test_redirects_are_rejected(self):
        error = HTTPError(
            "https://technocore.chat/r/lobby",
            302,
            "Found",
            {"Location": "http://example.test/"},
            None,
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaisesRegex(agent.NetworkError, "redirects are refused"):
                agent.request_json(Request("https://technocore.chat/r/lobby"), 1)

    def test_proof_file_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_bytes(b"{" + b" " * agent.MAX_PROOF_BYTES)
            args = agent.build_parser().parse_args(["verify-proof", str(path)])
            with self.assertRaisesRegex(agent.LocalFileError, "safety limit"):
                agent.run_command(args)


class AutoChatTests(unittest.TestCase):
    def test_defaults_to_questions_and_ignores_self(self):
        own = "did:key:z6Mk" + "x" * 44
        self.assertTrue(
            agent.should_auto_reply(
                {"from": "human", "text": "What do you think?"}, own, False
            )
        )
        self.assertFalse(
            agent.should_auto_reply(
                {"from": "human", "text": "A plain statement."}, own, False
            )
        )
        self.assertFalse(
            agent.should_auto_reply(
                {"from": own, "text": "Reply to me?"}, own, True
            )
        )

    def test_template_provider_needs_no_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            reply, source = agent.choose_auto_reply(
                [{"from": "human", "text": "Any ideas?"}],
                "template",
                agent.DEFAULT_GROQ_MODEL,
                agent.DEFAULT_GEMINI_MODEL,
                1,
            )
        self.assertEqual(source, "template")
        self.assertIn(reply, agent.FALLBACK_REPLIES)

    def test_provider_requests_use_current_model_and_application_user_agent(self):
        context = [{"from": "human", "text": "What should we test?"}]
        groq_response = MagicMock()
        groq_response.__enter__.return_value.read.return_value = json.dumps(
            {"choices": [{"message": {"content": "Test the trust boundary."}}]}
        ).encode()
        gemini_response = MagicMock()
        gemini_response.__enter__.return_value.read.return_value = json.dumps(
            {
                "candidates": [
                    {"content": {"parts": [{"text": "Test failure handling."}]}}
                ]
            }
        ).encode()
        with patch.object(
            agent.HTTP_OPENER, "open", side_effect=[groq_response, gemini_response]
        ) as opened:
            agent.generate_groq_reply(
                context, "secret", agent.DEFAULT_GROQ_MODEL, 1
            )
            agent.generate_gemini_reply(
                context, "secret", agent.DEFAULT_GEMINI_MODEL, 1
            )
        groq_request = opened.call_args_list[0].args[0]
        gemini_request = opened.call_args_list[1].args[0]
        expected_agent = f"technocore-did-starter/{agent.APP_VERSION}"
        self.assertEqual(groq_request.get_header("User-agent"), expected_agent)
        self.assertEqual(gemini_request.get_header("User-agent"), expected_agent)
        self.assertIn(b'"model":"openai/gpt-oss-20b"', groq_request.data)
        self.assertIn("gemini-3.7-flash", gemini_request.full_url)
        self.assertIn(b'"thinkingLevel":"low"', gemini_request.data)
        self.assertIn(b'"maxOutputTokens":512', gemini_request.data)

    def test_auto_state_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            expected = {"last_seq": 42, "sent_at": [1.5, 2.5]}
            agent.save_auto_state(path, expected)
            self.assertEqual(agent.load_auto_state(path), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_auto_chat_is_dry_run_by_default(self):
        args = agent.build_parser().parse_args(["auto-chat"])
        self.assertFalse(args.send)
        self.assertFalse(args.respond_all)
        self.assertEqual(args.room, "chat")

    def test_dry_run_proposes_without_posting(self):
        key = Ed25519PrivateKey.generate()
        incoming = {
            "room": "chat",
            "count": 1,
            "last_seq": 11,
            "messages": [
                {"seq": 11, "from": "human", "text": "What should we test?"}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                cooldown=180.0,
                max_per_hour=3,
                max_replies=1,
                state=Path(directory) / "state.json",
                since=10,
                room="chat",
                context=10,
                base_url=agent.DEFAULT_BASE_URL,
                timeout=1.0,
                wait=1.0,
                respond_all=False,
                provider="template",
                groq_model=agent.DEFAULT_GROQ_MODEL,
                gemini_model=agent.DEFAULT_GEMINI_MODEL,
                generation_timeout=1.0,
                send=False,
            )
            with patch.object(agent, "follow_room", return_value=iter([incoming])), patch.object(
                agent, "post_signed_message"
            ) as post:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(agent.run_auto_chat(key, args), 0)
                post.assert_not_called()
            self.assertEqual(agent.load_auto_state(args.state)["last_seq"], 11)


class AutoPostTests(unittest.TestCase):
    def test_dry_run_previews_one_message_and_rotates_room(self):
        key = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                interval=60.0,
                max_posts=1,
                rooms=["chat", "lobby"],
                state=Path(directory) / "post-state.json",
                send=False,
                base_url=agent.DEFAULT_BASE_URL,
                timeout=1.0,
            )
            output = io.StringIO()
            with patch.object(agent, "post_signed_message") as post, redirect_stdout(output):
                self.assertEqual(agent.run_auto_post(key, args), 0)
                post.assert_not_called()
            preview = json.loads(output.getvalue())
            self.assertEqual(preview["room"], "chat")
            self.assertIn(preview["text"], agent.CONVERSATION_STARTERS)
            state = agent.load_auto_post_state(args.state)
            self.assertEqual(state["room_index"], 1)

    def test_auto_post_requires_multiple_unique_rooms(self):
        key = Ed25519PrivateKey.generate()
        base = dict(
            interval=60.0,
            max_posts=1,
            state=Path("unused-state.json"),
            send=False,
            base_url=agent.DEFAULT_BASE_URL,
            timeout=1.0,
        )
        with self.assertRaisesRegex(agent.ProtocolError, "at least two"):
            agent.run_auto_post(key, SimpleNamespace(rooms=["chat"], **base))
        with self.assertRaisesRegex(agent.ProtocolError, "duplicates"):
            agent.run_auto_post(key, SimpleNamespace(rooms=["chat", "chat"], **base))

    def test_auto_post_interval_has_safe_minimum(self):
        key = Ed25519PrivateKey.generate()
        args = SimpleNamespace(
            interval=59.0,
            max_posts=1,
            rooms=["chat", "lobby"],
            state=Path("unused-state.json"),
            send=False,
            base_url=agent.DEFAULT_BASE_URL,
            timeout=1.0,
        )
        with self.assertRaisesRegex(agent.ProtocolError, "at least 60"):
            agent.run_auto_post(key, args)


class ConfigurationTests(unittest.TestCase):
    def test_config_defaults_and_environment_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "auto_chat": {"room": "from-config", "cooldown": 240},
                        "auto_post": {"rooms": ["chat", "lobby"]},
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "TECHNOCORE_CONFIG": str(path),
                "TECHNOCORE_AUTO_CHAT_ROOM": "from-env",
            }
            with patch.dict("os.environ", environment, clear=True):
                chat = agent.build_parser().parse_args(["auto-chat"])
                post = agent.build_parser().parse_args(["auto-post"])
            self.assertEqual(chat.room, "from-env")
            self.assertEqual(chat.cooldown, 240)
            self.assertEqual(post.rooms, ["chat", "lobby"])

    def test_config_rejects_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"server":{"typo":1}}', encoding="utf-8")
            with patch.dict(
                "os.environ", {"TECHNOCORE_CONFIG": str(path)}, clear=True
            ), self.assertRaisesRegex(agent.ProtocolError, "unknown field"):
                agent.build_parser()

    def test_runner_loads_env_without_overwriting_process_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "# comment\nGROQ_API_KEY=from-file\n"
                "GEMINI_API_KEY='quoted-value'\nLITERAL=$(not-executed)\n",
                encoding="utf-8",
            )
            with patch.dict("os.environ", {"GROQ_API_KEY": "existing"}, clear=True):
                runner.load_env_file(path)
                self.assertEqual(os.environ["GROQ_API_KEY"], "existing")
                self.assertEqual(os.environ["GEMINI_API_KEY"], "quoted-value")
                self.assertEqual(os.environ["LITERAL"], "$(not-executed)")

    def test_runner_rejects_invalid_env_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("not an assignment\n", encoding="utf-8")
            with self.assertRaisesRegex(agent.ProtocolError, "expected NAME=VALUE"):
                runner.load_env_file(path)


if __name__ == "__main__":
    unittest.main()
