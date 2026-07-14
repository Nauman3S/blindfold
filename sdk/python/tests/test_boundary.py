from __future__ import annotations

from dataclasses import dataclass
import asyncio
import re
import unittest

from blindfold import (
    Boundary,
    BoundaryClosedError,
    InvalidSafeRefError,
    ProtectionMode,
    RegistryConflictError,
    RestorationError,
    SensitiveValueError,
    UnsupportedPayloadError,
)


TOKEN_PATTERN = re.compile(
    r"^\{\{BLINDFOLD:SDK:v1:(SECRET|PII):[0-9a-f]{32}\}\}$"
)


class BoundaryTests(unittest.TestCase):
    def test_masks_registered_values_longest_first(self) -> None:
        boundary = Boundary(pii=["alice", "alice@example.test"], secrets=["fake-key"])

        protected = boundary.protect("Email alice@example.test using fake-key")

        self.assertEqual(protected.replacements, 2)
        self.assertNotIn("alice", protected.text)
        self.assertNotIn("fake-key", protected.text)

    def test_safe_refs_are_stable_per_session_and_unpredictable_between_sessions(self) -> None:
        first = Boundary()
        second = Boundary()

        first_token = first.register_pii("alice@example.test")

        self.assertRegex(first_token, TOKEN_PATTERN)
        self.assertEqual(first.register_pii("alice@example.test"), first_token)
        self.assertNotEqual(second.register_pii("alice@example.test"), first_token)

    def test_rejects_conflicting_classification(self) -> None:
        boundary = Boundary(secrets=["ambiguous"])

        with self.assertRaises(RegistryConflictError):
            boundary.register_pii("ambiguous")

    def test_redact_is_irreversible(self) -> None:
        boundary = Boundary(secrets=["fake-key"], pii=["alice@example.test"])

        protected = boundary.protect(
            "alice@example.test fake-key", mode=ProtectionMode.REDACT
        )

        self.assertEqual(
            protected.text,
            "[BLINDFOLD_REDACTED_PII] [BLINDFOLD_REDACTED_SECRET]",
        )
        self.assertEqual(
            boundary.restore(protected.text, destination="end_user"), protected.text
        )

    def test_block_mode_fails_before_transport(self) -> None:
        calls: list[str] = []
        boundary = Boundary(secrets=["fake-key"], mode="block")

        def send(text: str) -> None:
            calls.append(text)

        protected_send = boundary.wrap_transport(send)
        with self.assertRaises(SensitiveValueError):
            protected_send("use fake-key")
        self.assertEqual(calls, [])

    def test_restores_pii_only_to_end_user(self) -> None:
        boundary = Boundary()
        token = boundary.register_pii("alice@example.test")

        self.assertEqual(
            boundary.restore(f"Contact {token}", destination="end_user"),
            "Contact alice@example.test",
        )
        for destination in ("llm", "log", "memory", "tool"):
            with self.subTest(destination=destination):
                with self.assertRaises(RestorationError):
                    boundary.restore(token, destination=destination)

    def test_never_restores_secrets(self) -> None:
        boundary = Boundary()
        token = boundary.register_secret("fake-key")

        for destination in ("end_user", "llm", "log", "memory", "tool"):
            with self.subTest(destination=destination):
                with self.assertRaises(RestorationError):
                    boundary.restore(token, destination=destination)

    def test_unknown_and_malformed_safe_refs_fail_closed(self) -> None:
        boundary = Boundary()
        forged = "{{BLINDFOLD:SDK:v1:PII:00000000000000000000000000000000}}"
        malformed = "{{BLINDFOLD:SDK:v1:PII:not-a-token}}"

        with self.assertRaises(InvalidSafeRefError):
            boundary.restore(forged, destination="end_user")
        with self.assertRaises(InvalidSafeRefError):
            boundary.restore(malformed, destination="end_user")

    def test_wrap_client_protects_nested_method_arguments(self) -> None:
        class Responses:
            def __init__(self) -> None:
                self.request: dict[str, object] | None = None

            def create(self, **request: object) -> dict[str, str]:
                self.request = request
                return {"output_text": "model output remains masked"}

        class Client:
            def __init__(self) -> None:
                self.responses = Responses()

        raw = Client()
        boundary = Boundary(secrets=["fake-key"], pii=["alice@example.test"])
        client = boundary.wrap(raw)

        result = client.responses.create(
            input=[
                {
                    "role": "user",
                    "content": "Email alice@example.test with fake-key",
                }
            ]
        )

        self.assertEqual(result["output_text"], "model output remains masked")
        request_text = repr(raw.responses.request)
        self.assertNotIn("alice@example.test", request_text)
        self.assertNotIn("fake-key", request_text)
        self.assertEqual(request_text.count("BLINDFOLD:SDK:v1"), 2)

    def test_wrap_client_protects_nested_provider_response(self) -> None:
        class Responses:
            def create(self, **request: object) -> dict[str, object]:
                return {
                    "output_text": "alice@example.test used fake-key",
                    "metadata": ["alice@example.test"],
                }

        class Client:
            responses = Responses()

        boundary = Boundary(secrets=["fake-key"], pii=["alice@example.test"])

        result = boundary.wrap(Client()).responses.create(input="hello")

        result_text = repr(result)
        self.assertNotIn("alice@example.test", result_text)
        self.assertNotIn("fake-key", result_text)
        self.assertEqual(result_text.count("BLINDFOLD:SDK:v1"), 3)
        self.assertEqual(
            boundary.restore(result["metadata"][0], destination="end_user"),
            "alice@example.test",
        )
        with self.assertRaises(RestorationError):
            boundary.restore(result["output_text"], destination="end_user")

    def test_wrap_client_protects_string_attributes_and_response_objects(self) -> None:
        class Result:
            output_text = "alice@example.test and fake-key"

            def model_dump(self) -> dict[str, str]:
                return {"output_text": self.output_text}

        class Responses:
            def create(self) -> Result:
                return Result()

        class Client:
            api_key = "fake-key"
            responses = Responses()

        boundary = Boundary(secrets=["fake-key"], pii=["alice@example.test"])
        client = boundary.wrap(Client())

        self.assertNotIn("fake-key", client.api_key)
        result = client.responses.create()
        self.assertNotIn("alice@example.test", result.output_text)
        self.assertNotIn("fake-key", result.output_text)
        self.assertNotIn("alice@example.test", repr(result.model_dump()))
        self.assertNotIn("fake-key", repr(result.model_dump()))

    def test_wrap_client_protects_async_provider_response(self) -> None:
        class Responses:
            async def create(self) -> str:
                return "alice@example.test"

        class Client:
            responses = Responses()

        boundary = Boundary(pii=["alice@example.test"])

        result = asyncio.run(boundary.wrap(Client()).responses.create())

        self.assertNotIn("alice@example.test", result)

    def test_streaming_provider_response_fails_closed(self) -> None:
        boundary = Boundary(secrets=["fake-key"])

        def send() -> object:
            yield "fake-key"

        with self.assertRaises(UnsupportedPayloadError):
            boundary.wrap_transport(send)()

    def test_protect_payload_supports_dataclasses_without_mutating_input(self) -> None:
        @dataclass(frozen=True)
        class Request:
            prompt: str
            tags: list[str]

        original = Request("use fake-key", ["alice@example.test"])
        boundary = Boundary(secrets=["fake-key"], pii=["alice@example.test"])

        protected = boundary.protect_payload(original)

        self.assertEqual(original.prompt, "use fake-key")
        self.assertNotIn("fake-key", protected.prompt)
        self.assertNotIn("alice@example.test", protected.tags)

    def test_bytes_containing_registered_value_fail_closed(self) -> None:
        boundary = Boundary(secrets=["fake-key"])

        with self.assertRaises(SensitiveValueError):
            boundary.protect_payload(b"upload fake-key")

    def test_cyclic_payload_fails_closed(self) -> None:
        boundary = Boundary()
        payload: list[object] = []
        payload.append(payload)

        with self.assertRaisesRegex(Exception, "cyclic"):
            boundary.protect_payload(payload)

    def test_context_manager_forgets_mappings_and_closes_boundary(self) -> None:
        with Boundary(secrets=["fake-key"]) as boundary:
            boundary.protect("fake-key")

        with self.assertRaises(BoundaryClosedError):
            boundary.protect("fake-key")

    def test_register_env_registers_value_without_mutating_source(self) -> None:
        environ = {"STRIPE_API_KEY": "fake-key"}
        boundary = Boundary()

        token = boundary.register_env("STRIPE_API_KEY", environ=environ)

        self.assertNotIn("fake-key", token)
        self.assertEqual(environ["STRIPE_API_KEY"], "fake-key")
        self.assertEqual(boundary.protect("use fake-key").text, f"use {token}")


if __name__ == "__main__":
    unittest.main()
