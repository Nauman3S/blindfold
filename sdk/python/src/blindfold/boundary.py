"""In-process text protection for calls to model clients and transports."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from functools import wraps
import inspect
import os
import re
import secrets
from threading import RLock
from typing import Any, ParamSpec, TypeVar, cast


class BlindfoldError(Exception):
    """Base class for SDK errors."""


class BoundaryClosedError(BlindfoldError):
    """Raised when a closed boundary is used."""


class RegistryConflictError(BlindfoldError):
    """Raised when one value is registered with conflicting classifications."""


class SensitiveValueError(BlindfoldError):
    """Raised when block mode encounters a registered value."""


class InvalidSafeRefError(BlindfoldError):
    """Raised when model output contains an unknown or malformed SafeRef."""


class RestorationError(BlindfoldError):
    """Raised when a destination is not authorized to restore a value."""


class UnsupportedPayloadError(BlindfoldError):
    """Raised when a payload cannot be inspected without risking a leak."""


class TokenKind(str, Enum):
    SECRET = "secret"
    PII = "pii"


class Destination(str, Enum):
    LLM = "llm"
    END_USER = "end_user"
    LOG = "log"
    MEMORY = "memory"
    TOOL = "tool"


class ProtectionMode(str, Enum):
    MASK = "mask"
    REDACT = "redact"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class ProtectedText:
    text: str
    replacements: int


@dataclass(frozen=True, slots=True)
class RegisteredValue:
    """A caller-identified sensitive value and its classification."""

    value: str
    kind: TokenKind | str


@dataclass(frozen=True, slots=True)
class _Mapping:
    kind: TokenKind
    value: str


_SAFE_REF_PATTERN = re.compile(
    r"\{\{BLINDFOLD:SDK:v1:(SECRET|PII):([0-9a-f]{32})\}\}"
)
_SAFE_REF_PREFIX = "{{BLINDFOLD"
_REDACTIONS = {
    TokenKind.SECRET: "[BLINDFOLD_REDACTED_SECRET]",
    TokenKind.PII: "[BLINDFOLD_REDACTED_PII]",
}
_SCALAR_TYPES = (type(None), bool, int, float, complex)

P = ParamSpec("P")
R = TypeVar("R")


class Boundary:
    """A short-lived registry and policy boundary for model-facing text.

    Values must be registered by the application. A boundary stores plaintext
    mappings in process memory and should be scoped to one logical session.
    """

    def __init__(
        self,
        *,
        secrets: tuple[str, ...] | list[str] = (),
        pii: tuple[str, ...] | list[str] = (),
        values: tuple[RegisteredValue, ...] | list[RegisteredValue] = (),
        mode: ProtectionMode | str = ProtectionMode.MASK,
    ) -> None:
        self._lock = RLock()
        self._mappings: dict[str, _Mapping] = {}
        self._value_index: dict[str, tuple[TokenKind, str]] = {}
        self._closed = False
        self._mode = _coerce_enum(ProtectionMode, mode, "mode")
        for value in secrets:
            self.register(value, TokenKind.SECRET)
        for value in pii:
            self.register(value, TokenKind.PII)
        for item in values:
            self.register(item.value, item.kind)

    def __enter__(self) -> Boundary:
        self._require_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def mode(self) -> ProtectionMode:
        return self._mode

    def register(self, value: str, kind: TokenKind | str) -> str:
        """Register a value and return its stable session SafeRef."""

        token_kind = _coerce_enum(TokenKind, kind, "kind")
        if not isinstance(value, str):
            raise TypeError("registered values must be strings")
        if not value:
            raise ValueError("cannot register an empty value")
        with self._lock:
            self._require_open()
            existing = self._value_index.get(value)
            if existing is not None:
                existing_kind, token = existing
                if existing_kind is not token_kind:
                    raise RegistryConflictError(
                        "the same value cannot be registered as both secret and PII"
                    )
                return token

            token = self._create_safe_ref(token_kind, value)
            self._mappings[token] = _Mapping(token_kind, value)
            self._value_index[value] = (token_kind, token)
            return token

    def register_secret(self, value: str) -> str:
        return self.register(value, TokenKind.SECRET)

    def register_pii(self, value: str) -> str:
        return self.register(value, TokenKind.PII)

    def register_env(
        self,
        name: str,
        *,
        kind: TokenKind | str = TokenKind.SECRET,
        environ: Mapping[str, str] | None = None,
    ) -> str:
        """Register a value from an environment variable.

        This does not remove or replace the variable in ``os.environ``. Process
        environment isolation belongs to the Blindfold CLI, not this SDK.
        """

        if not isinstance(name, str):
            raise TypeError("environment variable name must be a string")
        if not name:
            raise ValueError("environment variable name cannot be empty")
        source = os.environ if environ is None else environ
        try:
            value = source[name]
        except KeyError as error:
            raise KeyError(f"environment variable is not set: {name}") from error
        return self.register(value, kind)

    def protect(
        self, text: str, *, mode: ProtectionMode | str | None = None
    ) -> ProtectedText:
        """Protect registered values in one model-facing string."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        selected_mode = self._mode if mode is None else _coerce_enum(
            ProtectionMode, mode, "mode"
        )
        with self._lock:
            self._require_open()
            matches = sorted(
                self._value_index.items(),
                key=lambda item: len(item[0]),
                reverse=True,
            )
            if selected_mode is ProtectionMode.BLOCK:
                if any(value in text for value, _ in matches):
                    raise SensitiveValueError(
                        "registered sensitive value blocked before model call"
                    )
                return ProtectedText(text, 0)

            chunks: list[str] = []
            replacements = 0
            offset = 0
            while offset < len(text):
                match = next(
                    (
                        (value, details)
                        for value, details in matches
                        if text.startswith(value, offset)
                    ),
                    None,
                )
                if match is None:
                    chunks.append(text[offset])
                    offset += 1
                    continue
                value, (kind, safe_ref) = match
                replacement = (
                    safe_ref
                    if selected_mode is ProtectionMode.MASK
                    else _REDACTIONS[kind]
                )
                chunks.append(replacement)
                replacements += 1
                offset += len(value)
            return ProtectedText("".join(chunks), replacements)

    def protect_payload(
        self, value: Any, *, mode: ProtectionMode | str | None = None
    ) -> Any:
        """Recursively protect strings in common provider request structures.

        Dictionaries, sequences, sets, dataclass instances, strings, bytes and
        scalar values are supported. Cyclic structures are rejected.
        """

        selected_mode = self._mode if mode is None else _coerce_enum(
            ProtectionMode, mode, "mode"
        )
        return self._protect_payload(value, selected_mode, set())

    def wrap(self, client: R, *, mode: ProtectionMode | str | None = None) -> R:
        """Wrap a provider client so method arguments are protected automatically."""

        self._require_open()
        if client is None:
            raise TypeError("client cannot be None")
        selected_mode = self._mode if mode is None else _coerce_enum(
            ProtectionMode, mode, "mode"
        )
        if callable(client):
            return cast(R, self.wrap_transport(client, mode=selected_mode))
        return cast(R, _ClientProxy(self, client, selected_mode))

    def wrap_transport(
        self,
        transport: Callable[P, R],
        *,
        mode: ProtectionMode | str | None = None,
    ) -> Callable[P, R]:
        """Wrap a callable transport and protect all of its call arguments."""

        self._require_open()
        if not callable(transport):
            raise TypeError("transport must be callable")
        selected_mode = self._mode if mode is None else _coerce_enum(
            ProtectionMode, mode, "mode"
        )

        @wraps(transport)
        def protected_transport(*args: P.args, **kwargs: P.kwargs) -> R:
            protected_args = self.protect_payload(args, mode=selected_mode)
            protected_kwargs = self.protect_payload(kwargs, mode=selected_mode)
            result = transport(*protected_args, **protected_kwargs)
            if inspect.isawaitable(result):
                return cast(R, self._protect_awaitable(result, selected_mode))
            return cast(R, self._protect_response(result, selected_mode, set()))

        return protected_transport

    def restore(self, text: str, *, destination: Destination | str) -> str:
        """Restore PII in model output only for an explicit end-user destination.

        Secrets are never restored through this method. Unknown, truncated and
        malformed SafeRefs fail closed.
        """

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        target = _coerce_enum(Destination, destination, "destination")
        with self._lock:
            self._require_open()
            self._validate_safe_refs(text)

            def restore_match(match: re.Match[str]) -> str:
                token = match.group(0)
                mapping = self._mappings[token]
                if mapping.kind is TokenKind.SECRET:
                    raise RestorationError(
                        "secret restoration is not allowed for model or user output"
                    )
                if target is not Destination.END_USER:
                    raise RestorationError(
                        "PII restoration requires the end_user destination"
                    )
                return mapping.value

            return _SAFE_REF_PATTERN.sub(restore_match, text)

    def close(self) -> None:
        """Forget mappings and permanently close this session boundary."""

        with self._lock:
            self._mappings.clear()
            self._value_index.clear()
            self._closed = True

    def _protect_payload(
        self, value: Any, mode: ProtectionMode, active_ids: set[int]
    ) -> Any:
        self._require_open()
        if isinstance(value, str):
            return self.protect(value, mode=mode).text
        if isinstance(value, bytes):
            for registered in self._registered_values():
                if registered.encode("utf-8") in value:
                    raise SensitiveValueError(
                        "registered value found in bytes; encode protected text instead"
                    )
            return value
        if isinstance(value, bytearray):
            for registered in self._registered_values():
                if registered.encode("utf-8") in value:
                    raise SensitiveValueError(
                        "registered value found in bytearray; encode protected text instead"
                    )
            return value
        if isinstance(value, _SCALAR_TYPES) or isinstance(value, Enum):
            return value

        track = isinstance(value, (Mapping, list, tuple, set, frozenset)) or is_dataclass(
            value
        )
        if track:
            identity = id(value)
            if identity in active_ids:
                raise BlindfoldError("cyclic payload structures are not supported")
            active_ids.add(identity)
        try:
            if isinstance(value, Mapping):
                protected_mapping: dict[Any, Any] = {}
                for key, item in value.items():
                    protected_key = self._protect_payload(key, mode, active_ids)
                    if protected_key in protected_mapping:
                        raise UnsupportedPayloadError(
                            "protection produced duplicate mapping keys"
                        )
                    protected_mapping[protected_key] = self._protect_payload(
                        item, mode, active_ids
                    )
                return protected_mapping
            if isinstance(value, list):
                return [self._protect_payload(item, mode, active_ids) for item in value]
            if isinstance(value, tuple):
                items = [self._protect_payload(item, mode, active_ids) for item in value]
                if hasattr(value, "_fields"):
                    return type(value)(*items)
                return tuple(items)
            if isinstance(value, set):
                return {self._protect_payload(item, mode, active_ids) for item in value}
            if isinstance(value, frozenset):
                return frozenset(
                    self._protect_payload(item, mode, active_ids) for item in value
                )
            if is_dataclass(value) and not isinstance(value, type):
                if any(not field.init for field in fields(value)):
                    raise UnsupportedPayloadError(
                        "dataclasses with init=False fields are not supported"
                    )
                updates = {
                    field.name: self._protect_payload(
                        getattr(value, field.name), mode, active_ids
                    )
                    for field in fields(value)
                    if field.init
                }
                return replace(value, **updates)
            if inspect.isgenerator(value) or inspect.isasyncgen(value):
                raise UnsupportedPayloadError(
                    "streaming request payloads are not supported"
                )
            if hasattr(value, "__dict__") or getattr(type(value), "__slots__", ()):
                raise UnsupportedPayloadError(
                    f"unsupported request payload type: {type(value).__name__}"
                )
            return value
        finally:
            if track:
                active_ids.remove(id(value))

    def _registered_values(self) -> tuple[str, ...]:
        with self._lock:
            self._require_open()
            return tuple(self._value_index)

    async def _protect_awaitable(
        self, awaitable: Any, mode: ProtectionMode
    ) -> Any:
        result = await awaitable
        return self._protect_response(result, mode, set())

    def _protect_response(
        self, value: Any, mode: ProtectionMode, active_ids: set[int]
    ) -> Any:
        """Protect a provider response without exposing an uninspected object."""

        self._require_open()
        if isinstance(value, str):
            return self.protect(value, mode=mode).text
        if isinstance(value, (bytes, bytearray)):
            for registered in self._registered_values():
                if registered.encode("utf-8") in value:
                    raise SensitiveValueError(
                        "registered value found in binary provider response"
                    )
            return value
        if isinstance(value, _SCALAR_TYPES) or isinstance(value, Enum):
            return value
        if inspect.isgenerator(value) or inspect.isasyncgen(value):
            close = getattr(value, "close", None)
            if callable(close):
                close()
            raise UnsupportedPayloadError(
                "streaming provider responses are not supported"
            )

        track = isinstance(value, (Mapping, list, tuple, set, frozenset)) or is_dataclass(
            value
        )
        if track:
            identity = id(value)
            if identity in active_ids:
                raise UnsupportedPayloadError("cyclic provider response is not supported")
            active_ids.add(identity)
        try:
            if isinstance(value, Mapping):
                protected_mapping: dict[Any, Any] = {}
                for key, item in value.items():
                    protected_key = self._protect_response(key, mode, active_ids)
                    if protected_key in protected_mapping:
                        raise UnsupportedPayloadError(
                            "protection produced duplicate response mapping keys"
                        )
                    protected_mapping[protected_key] = self._protect_response(
                        item, mode, active_ids
                    )
                return protected_mapping
            if isinstance(value, list):
                return [self._protect_response(item, mode, active_ids) for item in value]
            if isinstance(value, tuple):
                items = [self._protect_response(item, mode, active_ids) for item in value]
                if hasattr(value, "_fields"):
                    return type(value)(*items)
                return tuple(items)
            if isinstance(value, set):
                protected = {
                    self._protect_response(item, mode, active_ids) for item in value
                }
                if len(protected) != len(value):
                    raise UnsupportedPayloadError(
                        "protection produced duplicate response set values"
                    )
                return protected
            if isinstance(value, frozenset):
                protected = frozenset(
                    self._protect_response(item, mode, active_ids) for item in value
                )
                if len(protected) != len(value):
                    raise UnsupportedPayloadError(
                        "protection produced duplicate response set values"
                    )
                return protected
            if is_dataclass(value) and not isinstance(value, type):
                if any(not field.init for field in fields(value)):
                    raise UnsupportedPayloadError(
                        "response dataclasses with init=False fields are not supported"
                    )
                updates = {
                    field.name: self._protect_response(
                        getattr(value, field.name), mode, active_ids
                    )
                    for field in fields(value)
                }
                return replace(value, **updates)
            if inspect.isawaitable(value):
                raise UnsupportedPayloadError(
                    "nested awaitables in provider responses are not supported"
                )
            return _ResponseProxy(self, value, mode)
        finally:
            if track:
                active_ids.remove(id(value))

    def _validate_safe_refs(self, text: str) -> None:
        offset = 0
        while True:
            start = text.find(_SAFE_REF_PREFIX, offset)
            if start < 0:
                return
            match = _SAFE_REF_PATTERN.match(text, start)
            if match is None:
                raise InvalidSafeRefError("malformed Blindfold SafeRef in model output")
            token = match.group(0)
            if token not in self._mappings:
                raise InvalidSafeRefError("unknown Blindfold SafeRef in model output")
            mapping = self._mappings[token]
            if match.group(1) != mapping.kind.value.upper():
                raise InvalidSafeRefError("SafeRef classification does not match registry")
            offset = match.end()

    def _create_safe_ref(self, kind: TokenKind, source: str) -> str:
        while True:
            token = (
                f"{{{{BLINDFOLD:SDK:v1:{kind.value.upper()}:"
                f"{secrets.token_hex(16)}}}}}"
            )
            if token in source or token in self._mappings:
                continue
            if any(token in mapping.value for mapping in self._mappings.values()):
                continue
            return token

    def _require_open(self) -> None:
        if self._closed:
            raise BoundaryClosedError("boundary session is closed")


class _ClientProxy:
    """A lazy proxy that protects arguments at any nested client method."""

    __slots__ = ("_boundary", "_client", "_mode")

    def __init__(
        self, boundary: Boundary, client: object, mode: ProtectionMode
    ) -> None:
        object.__setattr__(self, "_boundary", boundary)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_mode", mode)

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._client, name)
        if callable(attribute):
            return self._boundary.wrap_transport(attribute, mode=self._mode)
        if isinstance(attribute, str):
            return self._boundary.protect(attribute, mode=self._mode).text
        if isinstance(attribute, (bytes, bytearray)):
            return self._boundary._protect_response(attribute, self._mode, set())
        if isinstance(attribute, _SCALAR_TYPES) or isinstance(attribute, Enum):
            return attribute
        if isinstance(attribute, (Mapping, list, tuple, set, frozenset)) or is_dataclass(
            attribute
        ):
            return self._boundary._protect_response(attribute, self._mode, set())
        return _ClientProxy(self._boundary, attribute, self._mode)

    def __repr__(self) -> str:
        return f"<BlindfoldClientProxy for {type(self._client).__name__}>"


class _ResponseProxy:
    """Expose response attributes only after applying the return-path policy."""

    __slots__ = ("_boundary", "_response", "_mode")

    def __init__(
        self, boundary: Boundary, response: object, mode: ProtectionMode
    ) -> None:
        object.__setattr__(self, "_boundary", boundary)
        object.__setattr__(self, "_response", response)
        object.__setattr__(self, "_mode", mode)

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._response, name)
        if callable(attribute):
            return self._boundary.wrap_transport(attribute, mode=self._mode)
        return self._boundary._protect_response(attribute, self._mode, set())

    def __repr__(self) -> str:
        return f"<BlindfoldResponseProxy for {type(self._response).__name__}>"


def _coerce_enum(enum_type: type[R], value: R | str, name: str) -> R:
    try:
        return enum_type(value)  # type: ignore[call-arg]
    except (TypeError, ValueError) as error:
        choices = ", ".join(item.value for item in enum_type)  # type: ignore[attr-defined]
        raise ValueError(f"{name} must be one of: {choices}") from error
