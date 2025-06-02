from __future__ import annotations

from dataclasses import dataclass
from inspect import iscoroutinefunction
from typing import Any, Callable, Iterator, TypeVar, TYPE_CHECKING

import httpx
from httpx import Request
from httpx._types import AuthTypes

from schemathesis.core import media_types, NotSet
from schemathesis.core.transforms import deepclone
from schemathesis.core.transport import Response
from schemathesis.core.errors import SerializationNotPossible
from schemathesis.transport.prepare import prepare_headers, prepare_url, prepare_body

if TYPE_CHECKING:
    from schemathesis.generation.case import Case


def get(app: Any):
    """Get transport to send the data to the application."""

    if app is None:
        return RequestsTransport
    if iscoroutinefunction(app) or (
        hasattr(app, "__call__") and iscoroutinefunction(app.__call__)  # noqa: B004
    ):
        return httpx.ASGITransport
    return httpx.WSGITransport


S = TypeVar("S", contravariant=True)


@dataclass
class SerializationContext:
    """Generic context for serialization process."""

    case: Case

    __slots__ = ("case",)


Serializer = Callable[[SerializationContext, Any], Any]


class TransportDriver:
    """Base class for transport drivers."""

    def __init__(self, transport: httpx.BaseTransport = None, app: Any = None) -> None:
        if transport is None:
            transport = get(app)
        self._transport = transport

    def get_initialized_transport(self, **kwargs) -> httpx.BaseTransport:
        app = kwargs.get("app", None)
        if app is not None:
            transport_kwargs = {"app": app}
        else:
            transport_kwargs = {}
        return self._transport(**transport_kwargs)

    def send(self, case: Case, _client: httpx.Client | None = None, **kwargs: Any) -> Response:
        """Send the case using this transport."""

        client = _client or httpx.Client(transport=self.get_initialized_transport(**kwargs))

        # TODO: ratelimiting
        # TODO: verify=False for wsgi/asgi
        try:
            response = client.send(**self.case_to_request(case, **kwargs))
        finally:
            if _client is None:
                client.close()
        return self.httpx_response_to_schemathesis_response(response, verify=kwargs.get("verify", True))

    async def send_async(self, case: Case, _client: httpx.AsyncClient | None = None, **kwargs: Any) -> Response:
        """Asynchronously send the case using this transport."""
        ...
        response = await client.send(**self.case_to_request(case, **kwargs))
        ...

    def case_to_request(
        self, case: Case, transport: httpx.BaseTransport, **kwargs: Any
    ) -> dict[str, Request | AuthTypes]:
        """Convert the case to a prepared httpx request."""
        result = {}

        base_url = prepare_url(case, kwargs.get("base_url"))
        headers = prepare_headers(case, kwargs.get("headers"))
        params = kwargs.get("params", {}) | case.query
        cookies = kwargs.get("cookies", {}) | case.cookies

        media_type = case.media_type

        # Set content type header if needed
        if (
            media_type
            and media_type not in ["multipart/form-data", "multipart/mixed"]
            and not isinstance(case.body, NotSet)
        ):
            if "content-type" not in headers:
                headers["Content-Type"] = media_type

        # Handle serialization
        if not isinstance(case.body, NotSet) and media_type is not None:
            serializer = transport._get_serializer(media_type)  # TODO: use SERIALIZERS_REGISTRY
            context = SerializationContext(case=case)
            extra = serializer(context, prepare_body(case))
        else:
            extra = {}

        # Additional headers from serializer
        headers.update(extra.pop("headers", {}))

        # Replace empty dictionaries with empty strings, so the parameters actually present in the query string
        if any(value == {} for value in (params or {}).values()):
            params = deepclone(params)
            for key, value in params.items():
                if value == {}:
                    params[key] = ""

        if case._auth is not None:
            result["auth"] = case._auth

        result["request"] = Request(
            method=case.method,
            url=base_url,
            params=params,
            headers=headers,
            cookies=cookies,
            **extra,
        )

        return result

    def httpx_response_to_schemathesis_response(self, response: httpx.Response, verify: bool) -> Response:
        """Convert the httpx response to the Schemathesis response."""
        return Response(
            status_code=response.status_code,
            headers=response.headers,
            content=response.content,
            request=response.request,
            elapsed=response.elapsed.total_seconds(),
            message=response.reason_phrase,
            encoding=response.encoding,
            http_version=response.http_version,
            verify=verify,
        )


class BaseTransport(httpx.BaseTransport):
    """Base implementation with serializer registration."""

    def __init__(self, *args, **kwargs) -> None:
        self._serializers: dict[str, Serializer] = {}  # TODO: rethink to avoid overriding init
        super().__init__(*args, **kwargs)

    def serializer(self, *media_types: str) -> Callable[[Serializer], Serializer]:
        """Register a serializer for given media types."""

        def decorator(func: Serializer) -> Serializer:
            for media_type in media_types:
                self._serializers[media_type] = func
            return func

        return decorator

    def unregister_serializer(self, *media_types: str) -> None:
        for media_type in media_types:
            self._serializers.pop(media_type, None)

    def _copy_serializers_from(self, transport: BaseTransport) -> None:
        self._serializers.update(transport._serializers)

    def get_first_matching_media_type(self, media_type: str) -> tuple[str, Serializer] | None:
        return next(self.get_matching_media_types(media_type), None)

    def get_matching_media_types(self, media_type: str) -> Iterator[tuple[str, Serializer]]:
        """Get all registered media types matching the given media type."""
        if media_type == "*/*":
            # Shortcut to avoid comparing all values
            yield from iter(self._serializers.items())
        else:
            main, sub = media_types.parse(media_type)
            checks = [
                media_types.is_json,
                media_types.is_xml,
                media_types.is_plain_text,
                media_types.is_yaml,
            ]
            for registered_media_type, serializer in self._serializers.items():
                # Try known variations for popular media types and fallback to comparison
                if any(check(media_type) and check(registered_media_type) for check in checks):
                    yield media_type, serializer
                else:
                    target_main, target_sub = media_types.parse(registered_media_type)
                    if main in ("*", target_main) and sub in ("*", target_sub):
                        yield registered_media_type, serializer

    def _get_serializer(self, input_media_type: str) -> Serializer:
        pair = self.get_first_matching_media_type(input_media_type)
        if pair is None:
            # This media type is set manually. Otherwise, it should have been rejected during the data generation
            raise SerializationNotPossible.for_media_type(input_media_type)
        return pair[1]
