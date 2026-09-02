import errno
import json
import io
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
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
            if os.name != "nt":
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

    def test_retryable_read_error_preserves_server_backoff(self):
        body = json.dumps({"retry_after": 60, "detail": "origin overloaded"}).encode()
        error = HTTPError(
            "https://technocore.chat/r/chat",
            502,
            "Bad Gateway",
            {},
            io.BytesIO(body),
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.RetryableNetworkError) as raised:
                agent.request_json(Request("https://technocore.chat/r/chat"), 1)
        self.assertEqual(raised.exception.retry_after, 60)

    def test_signed_write_error_is_never_marked_retryable(self):
        error = HTTPError(
            "https://technocore.chat/r/chat",
            502,
            "Bad Gateway",
            {},
            io.BytesIO(b'{"retry_after":60}'),
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.NetworkError) as raised:
                agent.request_json(
                    Request("https://technocore.chat/r/chat"), 1, is_write=True
                )
        self.assertNotIsInstance(raised.exception, agent.RetryableNetworkError)

    def test_follow_room_resumes_after_retryable_read_error(self):
        did = agent.did_from_private_key(Ed25519PrivateKey.generate())
        response = {
            "room": "chat",
            "count": 1,
            "last_seq": 11,
            "messages": [
                {"seq": 11, "from": did, "text": "hello", "nonce": 11}
            ],
        }
        retryable = agent.RetryableNetworkError("temporary failure", 2)
        with patch.object(
            agent, "read_room", side_effect=[retryable, response]
        ), patch.object(agent.time, "sleep") as sleep, patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            followed = agent.follow_room("chat", since=10, wait=1, timeout=2)
            self.assertEqual(next(followed), response)
        sleep.assert_called_once_with(agent.FOLLOW_RETRY_BASE_SECONDS)

    def test_follow_room_backoff_grows_and_is_capped(self):
        response = {
            "room": "chat",
            "count": 1,
            "last_seq": 11,
            "messages": [{"seq": 11, "from": "human", "text": "back", "nonce": None}],
        }
        retryable = agent.RetryableNetworkError("origin blip", 1)
        with patch.object(
            agent, "read_room", side_effect=[retryable] * 6 + [response]
        ), patch.object(agent.time, "sleep") as sleep, patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            followed = agent.follow_room("chat", since=10, wait=1, timeout=2)
            self.assertEqual(next(followed), response)
        waited = [call.args[0] for call in sleep.call_args_list]
        self.assertEqual(waited, [5.0, 10.0, 20.0, 40.0, 60.0, 60.0])
        self.assertTrue(all(value <= agent.FOLLOW_RETRY_CAP_SECONDS for value in waited))

    def test_follow_room_drops_long_poll_after_repeated_failures(self):
        response = {
            "room": "chat",
            "count": 1,
            "last_seq": 11,
            "messages": [{"seq": 11, "from": "human", "text": "back", "nonce": None}],
        }
        retryable = agent.RetryableNetworkError("origin blip", 1)
        calls = []

        def record(room, **kwargs):
            calls.append(kwargs)
            if len(calls) <= agent.FOLLOW_PLAIN_POLL_AFTER:
                raise retryable
            return response

        with patch.object(
            agent, "read_room", side_effect=record
        ), patch.object(agent.time, "sleep"), patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            followed = agent.follow_room("chat", since=10, wait=5, timeout=20)
            self.assertEqual(next(followed), response)

        self.assertEqual(calls[0]["wait"], 5.0)
        self.assertEqual(calls[0]["cache_buster"], 0)
        degraded = calls[agent.FOLLOW_PLAIN_POLL_AFTER]
        self.assertIsNone(degraded["wait"])
        self.assertIsNone(degraded["cache_buster"])

    def test_read_room_resilient_rides_out_a_startup_blip(self):
        ok = {"room": "chat", "count": 0, "last_seq": 3, "messages": []}
        blip = agent.RetryableNetworkError("origin blip", 1)
        with patch.object(
            agent, "read_room", side_effect=[blip, blip, ok]
        ), patch.object(agent.time, "sleep") as sleep, patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(agent.read_room_resilient("chat"), ok)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [5.0, 10.0])

    def test_read_room_resilient_gives_up_after_its_attempt_budget(self):
        blip = agent.RetryableNetworkError("origin blip", 1)
        with patch.object(
            agent, "read_room", side_effect=blip
        ) as read, patch.object(agent.time, "sleep"), patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(agent.RetryableNetworkError):
                agent.read_room_resilient("chat", attempts=3)
        self.assertEqual(read.call_count, 3)

    def test_transport_error_is_retryable_split_by_direction(self):
        no_route = OSError(errno.ENETUNREACH, "Network is unreachable")
        self.assertTrue(agent.transport_error_is_retryable(no_route, is_write=True))
        self.assertTrue(agent.transport_error_is_retryable(no_route, is_write=False))
        dns = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        self.assertTrue(agent.transport_error_is_retryable(dns, is_write=True))
        reset = OSError(errno.ECONNRESET, "Connection reset by peer")
        self.assertFalse(agent.transport_error_is_retryable(reset, is_write=True))
        self.assertTrue(agent.transport_error_is_retryable(reset, is_write=False))
        opaque = OSError(errno.EACCES, "permission denied")
        self.assertFalse(agent.transport_error_is_retryable(opaque, is_write=True))
        self.assertFalse(agent.transport_error_is_retryable("tls handshake", is_write=False))

    def test_unreachable_network_is_retryable_even_for_a_write(self):
        error = URLError(OSError(errno.ENETUNREACH, "Network is unreachable"))
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.RetryableNetworkError):
                agent.request_json(
                    Request("https://technocore.chat/r/chat"), 1, is_write=True
                )

    def test_unknown_transport_failure_stays_fatal_for_a_write(self):
        error = URLError("unverified TLS certificate")
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.NetworkError) as raised:
                agent.request_json(
                    Request("https://technocore.chat/r/chat"), 1, is_write=True
                )
        self.assertNotIsInstance(raised.exception, agent.RetryableNetworkError)

    def test_post_resends_with_the_same_nonce_after_a_pre_send_failure(self):
        key = Ed25519PrivateKey.generate()
        sent = []

        def fake_request_json(request, timeout, *, is_write=False):
            payload = json.loads(request.data.decode("utf-8"))
            sent.append(payload)
            if len(sent) == 1:
                raise agent.RetryableNetworkError("could not reach Technocore", 5.0)
            return {
                "room": "chat",
                "count": 1,
                "last_seq": 4,
                "messages": [
                    {
                        "seq": 4,
                        "from": payload["did"],
                        "text": payload["text"],
                        "nonce": payload["nonce"],
                    }
                ],
                "posted": {
                    "seq": 4,
                    "from": payload["did"],
                    "text": payload["text"],
                    "nonce": payload["nonce"],
                },
            }

        with patch.object(
            agent, "request_json", side_effect=fake_request_json
        ), patch.object(agent.time, "sleep"), patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            response = agent.post_signed_message(key, "chat", "hello world", nonce=7)

        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]["nonce"], sent[1]["nonce"])
        self.assertEqual(sent[0]["nonce"], "7")
        self.assertEqual(response["posted"]["seq"], 4)

    def test_post_stops_after_the_transport_retry_budget(self):
        key = Ed25519PrivateKey.generate()
        calls = []

        def always_unreachable(request, timeout, *, is_write=False):
            calls.append(1)
            raise agent.RetryableNetworkError("could not reach Technocore", 5.0)

        with patch.object(
            agent, "request_json", side_effect=always_unreachable
        ), patch.object(agent.time, "sleep"), patch.object(
            agent.random, "uniform", return_value=1.0
        ), patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(agent.RetryableNetworkError):
                agent.post_signed_message(
                    key, "chat", "hello world", nonce=7, transport_retries=2
                )
        self.assertEqual(len(calls), 3)

    def test_stale_nonce_write_is_classified_for_retry(self):
        body = (
            "400 nonce 1787897806837922159 is not greater than "
            "1787897807376081293, the last one this key used in /r/technocore "
            "— a signed URL is single-use, so count up"
        )
        error = HTTPError(
            "https://technocore.chat/r/technocore",
            400,
            "Bad Request",
            {},
            io.BytesIO(json.dumps({"detail": body}).encode()),
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.NonceRejectedError) as raised:
                agent.request_json(
                    Request("https://technocore.chat/r/technocore"), 1, is_write=True
                )
        self.assertEqual(raised.exception.last_nonce, 1787897807376081293)

    def test_other_write_400_is_not_a_nonce_error(self):
        error = HTTPError(
            "https://technocore.chat/r/chat",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"detail":"room name is invalid"}'),
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.NetworkError) as raised:
                agent.request_json(
                    Request("https://technocore.chat/r/chat"), 1, is_write=True
                )
        self.assertNotIsInstance(raised.exception, agent.NonceRejectedError)

    def test_read_400_never_looks_for_a_nonce(self):
        error = HTTPError(
            "https://technocore.chat/r/chat",
            400,
            "Bad Request",
            {},
            io.BytesIO(b"nonce 1 is not greater than 9, count up"),
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.NetworkError) as raised:
                agent.request_json(Request("https://technocore.chat/r/chat"), 1)
        self.assertNotIsInstance(raised.exception, agent.NonceRejectedError)

    def test_nonce_after_counts_past_the_servers_value(self):
        self.assertGreater(int(agent.nonce_after(10**18)), 10**18)
        self.assertRegex(agent.nonce_after(10**18), r"\A[0-9]{1,19}\Z")
        with self.assertRaises(agent.ProtocolError):
            agent.nonce_after(agent.MAX_NONCE)

    def test_parse_rejected_nonce_reads_the_servers_value(self):
        self.assertEqual(
            agent.parse_rejected_nonce(b"nonce 5 is not greater than 42, count up"),
            42,
        )
        self.assertIsNone(agent.parse_rejected_nonce(b"unrelated bad request"))

    def test_post_retries_with_a_higher_nonce_after_a_stale_nonce(self):
        key = Ed25519PrivateKey.generate()
        sent = []

        def fake_request_json(request, timeout, *, is_write=False):
            payload = json.loads(request.data.decode("utf-8"))
            sent.append(payload)
            if len(sent) == 1:
                raise agent.NonceRejectedError("stale nonce", 10**18)
            return {
                "room": "chat",
                "count": 1,
                "last_seq": 7,
                "messages": [
                    {
                        "seq": 7,
                        "from": payload["did"],
                        "text": payload["text"],
                        "nonce": payload["nonce"],
                    }
                ],
                "posted": {
                    "seq": 7,
                    "from": payload["did"],
                    "text": payload["text"],
                    "nonce": payload["nonce"],
                },
            }

        with patch.object(
            agent, "request_json", side_effect=fake_request_json
        ), patch("sys.stderr", new=io.StringIO()):
            response = agent.post_signed_message(key, "chat", "hello world", nonce=1)

        self.assertEqual(len(sent), 2)
        self.assertEqual(int(sent[0]["nonce"]), 1)
        self.assertGreater(int(sent[1]["nonce"]), 10**18)
        self.assertEqual(response["posted"]["seq"], 7)

    def test_post_stops_after_the_nonce_retry_budget(self):
        key = Ed25519PrivateKey.generate()
        attempts = []

        def always_stale(request, timeout, *, is_write=False):
            attempts.append(json.loads(request.data.decode("utf-8"))["nonce"])
            raise agent.NonceRejectedError("stale nonce", 10**18 + len(attempts))

        with patch.object(
            agent, "request_json", side_effect=always_stale
        ), patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(agent.NonceRejectedError):
                agent.post_signed_message(
                    key, "chat", "hello world", nonce=1, nonce_retries=2
                )

        self.assertEqual(len(attempts), 3)

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

    def test_empty_provider_output_is_recoverable(self):
        with self.assertRaisesRegex(agent.NetworkError, "invalid text"):
            agent.validate_generated_reply("   \n\t")

        context = [{"from": "human", "text": "Any ideas?"}]
        with patch.dict("os.environ", {"GROQ_API_KEY": "configured"}, clear=True), patch.object(
            agent,
            "generate_groq_reply",
            side_effect=agent.NetworkError("generation provider returned invalid text"),
        ), patch("sys.stderr", new=io.StringIO()):
            reply, source = agent.choose_auto_reply(
                context,
                "auto",
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
        self.assertIn(b'"reasoning_effort":"low"', groq_request.data)
        self.assertIn(b'"max_completion_tokens":512', groq_request.data)
        self.assertIn("gemini-3.7-flash", gemini_request.full_url)
        self.assertIn(b'"thinkingLevel":"low"', gemini_request.data)
        self.assertIn(b'"maxOutputTokens":1024', gemini_request.data)

    def test_truncated_provider_output_is_rejected_not_posted(self):
        cut = "Thanks for the update! Looks like the Technocore"
        groq_truncated = MagicMock()
        groq_truncated.__enter__.return_value.read.return_value = json.dumps(
            {"choices": [{"message": {"content": cut}, "finish_reason": "length"}]}
        ).encode()
        with patch.object(agent.HTTP_OPENER, "open", return_value=groq_truncated):
            with self.assertRaisesRegex(agent.NetworkError, "truncated"):
                agent.generate_groq_reply(
                    [{"from": "human", "text": "hi"}], "secret",
                    agent.DEFAULT_GROQ_MODEL, 1,
                )

        gemini_truncated = MagicMock()
        gemini_truncated.__enter__.return_value.read.return_value = json.dumps(
            {"candidates": [
                {"content": {"parts": [{"text": cut}]}, "finishReason": "MAX_TOKENS"}
            ]}
        ).encode()
        with patch.object(agent.HTTP_OPENER, "open", return_value=gemini_truncated):
            with self.assertRaisesRegex(agent.NetworkError, "truncated"):
                agent.generate_gemini_reply(
                    [{"from": "human", "text": "hi"}], "secret",
                    agent.DEFAULT_GEMINI_MODEL, 1,
                )

        openai_incomplete = MagicMock()
        openai_incomplete.__enter__.return_value.read.return_value = json.dumps(
            {"status": "incomplete",
             "incomplete_details": {"reason": "max_output_tokens"},
             "output_text": cut}
        ).encode()
        with patch.object(agent.HTTP_OPENER, "open", return_value=openai_incomplete):
            with self.assertRaisesRegex(agent.NetworkError, "incomplete"):
                agent.generate_openai_reply(
                    [{"from": "human", "text": "hi"}], "secret",
                    agent.DEFAULT_OPENAI_MODEL, 1,
                )

    def test_openai_response_request_and_nested_output(self):
        context = [{"from": "human", "text": "What should we test?"}]
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "output": [
                    {"content": [{"type": "output_text", "text": "Test fallback routing."}]}
                ]
            }
        ).encode()
        with patch.object(agent.HTTP_OPENER, "open", return_value=response) as opened:
            reply = agent.generate_openai_reply(
                context, "secret", agent.DEFAULT_OPENAI_MODEL, 1
            )
        request = opened.call_args.args[0]
        self.assertEqual(reply, "Test fallback routing.")
        self.assertEqual(request.full_url, "https://api.openai.com/v1/responses")
        self.assertIn(b'"model":"gpt-5.4-mini"', request.data)
        self.assertIn(b'"store":false', request.data)

    def test_provider_429_reads_the_wait_from_the_body_when_no_header(self):
        body = json.dumps({"error": {
            "message": "Rate limit reached for model X on tokens per day (TPD): "
                       "Limit 200000, Used 199480. Please try again in 5m31.344s.",
            "code": "rate_limit_exceeded",
        }}).encode()
        error = HTTPError(
            "https://api.groq.com/openai/v1/chat/completions", 429,
            "Too Many Requests", {}, io.BytesIO(body),
        )
        with patch.object(agent.HTTP_OPENER, "open", side_effect=error):
            with self.assertRaises(agent.ProviderNetworkError) as raised:
                agent.request_external_json(
                    Request("https://api.groq.com/openai/v1/chat/completions"), 1, "Groq"
                )
        self.assertAlmostEqual(raised.exception.retry_after, 331.344, places=2)

    def test_auto_provider_uses_twelve_hour_schedule_and_fallback(self):
        context = [{"from": "human", "text": "Any ideas?"}]
        keys = {
            "GROQ_API_KEY": "groq",
            "GEMINI_API_KEY": "gemini",
            "OPENAI_API_KEY": "openai",
        }
        with patch.dict("os.environ", keys, clear=True), patch.object(
            agent, "generate_groq_reply", side_effect=agent.NetworkError("groq limit")
        ), patch.object(
            agent, "generate_gemini_reply", side_effect=agent.NetworkError("gemini limit")
        ), patch.object(
            agent, "generate_openai_reply", return_value="OpenAI fallback"
        ) as openai, patch("sys.stderr", new=io.StringIO()):
            reply, source = agent.choose_auto_reply(
                context, "auto", agent.DEFAULT_GROQ_MODEL,
                agent.DEFAULT_GEMINI_MODEL, 1, utc_hour=2
            )
        self.assertEqual((reply, source), ("OpenAI fallback", "openai"))
        openai.assert_called_once()

        with patch.dict("os.environ", keys, clear=True), patch.object(
            agent, "generate_openai_reply", return_value="OpenAI scheduled"
        ) as openai:
            reply, source = agent.choose_auto_reply(
                context, "auto", agent.DEFAULT_GROQ_MODEL,
                agent.DEFAULT_GEMINI_MODEL, 1, utc_hour=13
            )
        self.assertEqual((reply, source), ("OpenAI scheduled", "openai"))
        openai.assert_called_once()

    def test_auto_state_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            expected = {"last_seq": 42, "sent_at": [1.5, 2.5]}
            agent.save_auto_state(path, expected)
            self.assertEqual(agent.load_auto_state(path), expected)
            if os.name != "nt":
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

    def test_failed_reply_write_is_unconfirmed_without_stopping_auto_chat(self):
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
                cooldown=300.0,
                max_per_hour=12,
                max_replies=0,
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
                send=True,
            )
            output = io.StringIO()
            errors = io.StringIO()
            with patch.object(
                agent, "follow_room", return_value=iter([incoming])
            ), patch.object(
                agent, "post_signed_message",
                side_effect=agent.NetworkError("Technocore returned HTTP 503"),
            ), redirect_stdout(output), patch("sys.stderr", new=errors):
                self.assertEqual(agent.run_auto_chat(key, args), 0)

            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "unconfirmed")
            self.assertEqual(result["reply_to"], 11)
            self.assertRegex(result["nonce"], r"\A[0-9]{1,19}\Z")
            self.assertIn("continuing to watch", errors.getvalue())
            state = agent.load_auto_state(args.state)
            self.assertEqual(state["last_seq"], 11)
            self.assertEqual(len(state["sent_at"]), 1)


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

    def test_auto_post_retries_the_room_after_a_failed_send(self):
        key = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                interval=60.0,
                max_posts=1,
                rooms=["chat", "lobby"],
                state=Path(directory) / "post-state.json",
                send=True,
                base_url=agent.DEFAULT_BASE_URL,
                timeout=1.0,
            )
            outcomes = [
                agent.NetworkError("could not reach Technocore: [Errno 101]"),
                {"posted": {"seq": 5, "nonce": "123"}},
            ]
            with patch.object(
                agent, "post_signed_message", side_effect=outcomes
            ) as post, patch.object(agent.time, "sleep"), redirect_stdout(
                io.StringIO()
            ), patch("sys.stderr", new=io.StringIO()) as errors:
                self.assertEqual(agent.run_auto_post(key, args), 0)
            self.assertEqual(post.call_count, 2)
            self.assertEqual(
                [call.args[1] for call in post.call_args_list], ["chat", "chat"]
            )
            self.assertIn("auto-post to chat failed", errors.getvalue())
            self.assertEqual(agent.load_auto_post_state(args.state)["room_index"], 1)

    def test_auto_post_state_round_trips_per_room_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            agent.save_auto_state(path, {
                "room_index": 2, "last_post_at": 5.0, "last_text": "hi",
                "day": "2026-09-01", "posts_today": {"chat": 3, "technocore": 1},
            })
            loaded = agent.load_auto_post_state(path)
            self.assertEqual(loaded["day"], "2026-09-01")
            self.assertEqual(loaded["posts_today"], {"chat": 3, "technocore": 1})
            # the flat integer written by an earlier build resets, never crashes
            agent.save_auto_state(path, {**loaded, "posts_today": 7})
            self.assertEqual(agent.load_auto_post_state(path)["posts_today"], {})
            # a genuinely corrupt per-room count is still rejected
            agent.save_auto_state(path, {**loaded, "posts_today": {"chat": -1}})
            with self.assertRaisesRegex(agent.LocalFileError, "invalid values"):
                agent.load_auto_post_state(path)

    def test_auto_post_daily_cap_is_per_room(self):
        key = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                interval=60.0, max_posts=0, max_per_day=1,
                rooms=["chat", "lobby"],
                state=Path(directory) / "post-state.json", send=True,
                base_url=agent.DEFAULT_BASE_URL, timeout=1.0, ledger=None,
            )
            posted = {"posted": {"seq": 5, "nonce": "123", "sig": "z" * 86}}

            def sleep(seconds):
                if seconds > 40000:  # the sleep-until-UTC-midnight nap
                    raise KeyboardInterrupt

            with patch.object(
                agent, "post_signed_message", return_value=posted
            ) as post, patch.object(
                agent, "seconds_until_utc_midnight", return_value=50000.0
            ), patch.object(
                agent.time, "sleep", side_effect=sleep
            ), redirect_stdout(io.StringIO()), patch(
                "sys.stderr", new=io.StringIO()
            ) as errors:
                with self.assertRaises(KeyboardInterrupt):
                    agent.run_auto_post(key, args)
            # one post to each room (cap is per room), then the whole-day nap
            self.assertEqual(post.call_count, 2)
            self.assertEqual(
                [call.args[1] for call in post.call_args_list], ["chat", "lobby"]
            )
            self.assertIn("1/room reached for every room", errors.getvalue())
            self.assertEqual(
                agent.load_auto_post_state(args.state)["posts_today"],
                {"chat": 1, "lobby": 1},
            )

    def test_seconds_until_utc_midnight_is_bounded(self):
        from datetime import datetime, timezone

        noon = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(agent.seconds_until_utc_midnight(noon), 12 * 3600)
        self.assertEqual(agent.utc_day(noon), "2026-09-01")


class RunnerSupervisorTests(unittest.TestCase):
    def _run(self, operation):
        shutdown = threading.Event()
        outcomes = {}
        with patch.object(shutdown, "wait", return_value=False), patch(
            "sys.stderr", new=io.StringIO()
        ):
            runner.supervise("w", operation, shutdown, outcomes)
        return outcomes

    def test_transient_crash_is_retried_then_settles(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise ValueError("boom")
            return 0

        self.assertEqual(self._run(flaky), {"w": "done"})
        self.assertEqual(calls["n"], 2)

    def test_misconfiguration_disables_the_worker_without_retry(self):
        calls = {"n": 0}

        def broken():
            calls["n"] += 1
            raise agent.ProtocolError("auto-post rooms are required")

        self.assertEqual(self._run(broken), {"w": "fatal"})
        self.assertEqual(calls["n"], 1)

    def test_clean_return_ends_the_worker(self):
        self.assertEqual(self._run(lambda: 0), {"w": "done"})

    def test_backoff_grows_across_repeated_crashes(self):
        shutdown = threading.Event()
        outcomes = {}
        waits = []
        attempts = {"n": 0}

        def wait(timeout=None):
            waits.append(timeout)
            return len(waits) >= 3  # let the third backoff end the worker

        def always_crashes():
            attempts["n"] += 1
            raise RuntimeError("boom")

        with patch.object(shutdown, "wait", side_effect=wait), patch(
            "sys.stderr", new=io.StringIO()
        ):
            runner.supervise("w", always_crashes, shutdown, outcomes)
        self.assertEqual(waits, [5.0, 10.0, 20.0])
        self.assertEqual(attempts["n"], 3)

    def test_resolve_home_room_prefers_env_then_config_then_empty(self):
        self.assertEqual(
            runner.resolve_home_room({}, {"TECHNOCORE_HOME_ROOM": " p-abc123 "}),
            "p-abc123",
        )
        self.assertEqual(
            runner.resolve_home_room({"auto_chat": {"home_room": "p-fromcfg"}}, {}),
            "p-fromcfg",
        )
        self.assertEqual(
            runner.resolve_home_room(
                {"auto_chat": {"home_room": "p-fromcfg"}},
                {"TECHNOCORE_HOME_ROOM": "p-fromenv"},
            ),
            "p-fromenv",
        )
        self.assertEqual(runner.resolve_home_room({}, {}), "")
        self.assertEqual(runner.resolve_home_room({}, {"TECHNOCORE_HOME_ROOM": "  "}), "")
        self.assertEqual(
            runner.resolve_home_room(
                {"auto_chat": {"home_room": "p-shared"}},
                {"TECHNOCORE_HOME_ROOM": "none"},
            ),
            "",
        )
        with self.assertRaises(agent.ProtocolError):
            runner.resolve_home_room({}, {"TECHNOCORE_HOME_ROOM": "Not A Room"})

    def test_home_state_path_never_collides_with_the_main_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            main_state = Path(directory) / ".technocore-auto-chat.json"
            home = runner.home_state_path(main_state, "p-279e665f44a04f1f3dd2b320")
            self.assertNotEqual(home, main_state)
            self.assertEqual(home.parent, main_state.parent)
            self.assertTrue(home.name.startswith(".technocore-"))
            self.assertIn("p-279e665f44a04f1f3dd2b320", home.name)


class RetainedSignatureTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.did = agent.did_from_private_key(self.key)

    def _msg(self, room, nonce, text, seq=1):
        normalized, payload = agent.message_payload(room, nonce, text)
        return {
            "seq": seq,
            "ts": "2026-09-01T00:00:00Z",
            "from": self.did,
            "text": normalized,
            "nonce": int(nonce),
            "sig": agent.sign_bytes(self.key, payload),
        }

    def test_message_signature_state_verifies_forges_and_abstains(self):
        good = self._msg("chat", 5, "hello world")
        self.assertIs(agent.message_signature_state(good, "chat"), True)
        self.assertIs(
            agent.message_signature_state({**good, "text": "tampered"}, "chat"), False
        )
        self.assertIs(agent.message_signature_state(good, "lobby"), False)
        self.assertIsNone(agent.message_signature_state({**good, "sig": None}, "chat"))
        self.assertIsNone(
            agent.message_signature_state({"from": "human", "text": "hi"}, "chat")
        )

    def test_read_room_tags_messages_and_warns_on_bad_signature(self):
        good = self._msg("chat", 5, "verified", seq=5)
        bad = {**self._msg("chat", 6, "forged", seq=6), "sig": "A" * 86}
        payload = {"room": "chat", "count": 2, "last_seq": 6, "messages": [good, bad]}
        with patch.object(agent, "request_json", return_value=payload), patch(
            "sys.stderr", new=io.StringIO()
        ) as err:
            out = agent.read_room("chat")
        self.assertIs(out["messages"][0]["sig_verified"], True)
        self.assertIs(out["messages"][1]["sig_verified"], False)
        self.assertIn("does NOT verify", err.getvalue())

    def test_validate_room_response_rejects_a_bad_generation(self):
        payload = {
            "room": "chat", "count": 0, "last_seq": 1,
            "generation": -1, "messages": [],
        }
        with self.assertRaisesRegex(agent.NetworkError, "generation"):
            agent.validate_room_response(payload, "chat")

    def test_follow_room_restarts_cursor_on_generation_change(self):
        first = {
            "room": "chat", "count": 1, "last_seq": 90, "generation": 3,
            "messages": [{"seq": 90, "from": "human", "text": "old epoch"}],
        }
        second = {
            "room": "chat", "count": 1, "last_seq": 2, "generation": 4,
            "messages": [{"seq": 2, "from": "human", "text": "new epoch"}],
        }
        with patch.object(
            agent, "read_room", side_effect=[first, second]
        ), patch.object(agent.time, "sleep"), patch("sys.stderr", new=io.StringIO()):
            stream = agent.follow_room("chat", since=80, wait=1, timeout=2)
            self.assertEqual(next(stream), first)
            self.assertEqual(next(stream), second)

    def test_post_enriches_the_posted_record_with_ts_and_sig(self):
        def fake(request, timeout, *, is_write=False):
            body = json.loads(request.data.decode("utf-8"))
            message = {
                "seq": 9, "ts": "2026-09-01T09:00:00Z", "from": body["did"],
                "text": body["text"], "nonce": int(body["nonce"]), "sig": body["sig"],
            }
            return {
                "room": "chat", "count": 1, "last_seq": 9, "messages": [message],
                "posted": {
                    "seq": 9, "from": body["did"],
                    "text": body["text"], "nonce": body["nonce"],
                },
            }

        with patch.object(agent, "request_json", side_effect=fake):
            response = agent.post_signed_message(self.key, "chat", "hello world", nonce=7)
        posted = response["posted"]
        self.assertEqual(posted["ts"], "2026-09-01T09:00:00Z")
        self.assertEqual(posted["room"], "chat")
        self.assertRegex(posted["sig"], r"\A[A-Za-z0-9_-]{86}\Z")

    def test_post_rejects_a_swapped_retained_signature(self):
        other = Ed25519PrivateKey.generate()

        def fake(request, timeout, *, is_write=False):
            body = json.loads(request.data.decode("utf-8"))
            _, payload = agent.message_payload("chat", body["nonce"], body["text"])
            bogus = agent.sign_bytes(other, payload)
            message = {
                "seq": 9, "from": body["did"], "text": body["text"],
                "nonce": int(body["nonce"]), "sig": bogus,
            }
            return {
                "room": "chat", "count": 1, "last_seq": 9, "messages": [message],
                "posted": {
                    "seq": 9, "from": body["did"], "text": body["text"],
                    "nonce": body["nonce"], "sig": bogus,
                },
            }

        with patch.object(agent, "request_json", side_effect=fake):
            with self.assertRaisesRegex(agent.NetworkError, "does not match this write"):
                agent.post_signed_message(self.key, "chat", "hello world", nonce=7)

    def test_append_signed_ledger_appends_one_line_per_post(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "ledger.jsonl"
            agent.append_signed_ledger(
                path, "chat",
                {"room": "chat", "seq": 1, "ts": "t1", "from": self.did,
                 "nonce": "10", "text": "one", "sig": "s1"},
            )
            agent.append_signed_ledger(
                path, "lobby",
                {"seq": 2, "ts": "t2", "from": self.did,
                 "nonce": "11", "text": "two", "sig": "s2"},
            )
            lines = path.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["schema"], agent.LEDGER_SCHEMA)
        self.assertEqual((first["room"], first["seq"], first["sig"]), ("chat", 1, "s1"))
        self.assertEqual(json.loads(lines[1])["room"], "lobby")

    def test_export_room_parses_jsonl_verifies_and_tallies(self):
        good = self._msg("chat", 5, "kept", seq=5)
        bad = {**self._msg("chat", 6, "x", seq=6), "sig": "B" * 86}
        jsonl = (json.dumps(good) + "\n" + json.dumps(bad) + "\n").encode("utf-8")
        opened = MagicMock()
        stream = opened.__enter__.return_value
        stream.read.return_value = jsonl
        stream.headers.get.return_value = "4"
        with patch.object(agent.HTTP_OPENER, "open", return_value=opened):
            dump = agent.export_room("chat")
        self.assertEqual(dump["count"], 2)
        self.assertEqual((dump["verified"], dump["forged"]), (1, 1))
        self.assertEqual(dump["generation"], 4)
        self.assertIs(dump["messages"][0]["sig_verified"], True)

    def test_auto_post_ledger_records_each_send(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "posts.jsonl"
            args = SimpleNamespace(
                interval=60.0, max_posts=1, rooms=["chat", "lobby"],
                state=Path(directory) / "state.json", send=True,
                base_url=agent.DEFAULT_BASE_URL, timeout=1.0, ledger=ledger,
            )
            posted = {
                "posted": {
                    "room": "chat", "seq": 5, "ts": "2026-09-01T09:00:00Z",
                    "from": self.did, "nonce": "123", "text": "hi", "sig": "z" * 86,
                }
            }
            with patch.object(
                agent, "post_signed_message", return_value=posted
            ), patch.object(agent.time, "sleep"), redirect_stdout(io.StringIO()), patch(
                "sys.stderr", new=io.StringIO()
            ):
                self.assertEqual(agent.run_auto_post(self.key, args), 0)
            entry = json.loads(ledger.read_text().splitlines()[0])
            self.assertEqual(entry["seq"], 5)
            self.assertEqual(entry["schema"], agent.LEDGER_SCHEMA)


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
