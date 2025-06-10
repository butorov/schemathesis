from __future__ import annotations

import binascii
import os
from io import BytesIO
from typing import TYPE_CHECKING, Any

import httpx
from httpx import ASGITransport, Request, Response, WSGITransport

from schemathesis.core.transforms import deepclone
from schemathesis.transport import SerializationContext
from schemathesis.transport.serialization import SERIALIZERS_REGISTRY, Binary, serialize_binary, serialize_xml

if TYPE_CHECKING:
    import requests


class RequestsTransport(httpx.BaseTransport):
    """Compatibility layer for using `requests` as a `httpx`'s transport."""

    def handle_request(self, request: Request) -> Response:
        # Convert the request to a requests.Request object
        req = requests.Request(
            method=request.method,
            url=request.url,
            headers=request.headers.raw,
            data=request.content,
            params=request.url.query,
            cookies=request.cookies,  # TODO
            auth=request.auth,  # TODO
        )
        with requests.Session() as session:
            response = session.send(session.prepare_request(req))
        return response


REQUESTS_TRANSPORT = RequestsTransport()


def _should_coerce_to_bytes(item: Any) -> bool:
    """Whether the item should be converted to bytes."""
    # These types are OK in forms, others should be coerced to bytes
    return isinstance(item, Binary) or not isinstance(item, (bytes, str, int))


def _prepare_form_data(data: dict[str, Any]) -> dict[str, Any]:
    """Make the generated data suitable for sending as multipart.

    If the schema is loose, Schemathesis can generate data that can't be sent as multipart. In these cases,
    we convert it to bytes and send it as-is, ignoring any conversion errors.

    NOTE. This behavior might change in the future.
    """
    for name, value in data.items():
        if isinstance(value, list):
            data[name] = [serialize_binary(item) if _should_coerce_to_bytes(item) else item for item in value]
        elif _should_coerce_to_bytes(value):
            data[name] = serialize_binary(value)
    return data


def choose_boundary() -> str:
    """Random boundary name."""
    return binascii.hexlify(os.urandom(16)).decode("ascii")


def _encode_multipart(value: Any, boundary: str) -> bytes:
    """Encode any value as multipart.

    NOTE. It doesn't aim to be 100% correct multipart payload, but rather a way to send data which is not intended to
    be used as multipart, in cases when the API schema dictates so.
    """
    # For such cases we stringify the value and wrap it to a randomly-generated boundary
    body = BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(str(value).encode())
    body.write(f"--{boundary}--\r\n".encode("latin-1"))
    return body.getvalue()


def multipart_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        return {"data": value}
    if isinstance(value, dict):
        value = deepclone(value)
        multipart = _prepare_form_data(value)
        files, data = ctx.case.operation.prepare_multipart(multipart)
        return {"files": files, "data": data}
    # Uncommon schema. For example - `{"type": "string"}`
    boundary = choose_boundary()
    raw_data = _encode_multipart(value, boundary)
    content_type = f"multipart/form-data; boundary={boundary}"
    return {"data": raw_data, "headers": {"Content-Type": content_type}}


SERIALIZERS_REGISTRY.register(
    [RequestsTransport, ASGITransport], ["multipart/form-data", "multipart/mixed"], multipart_serializer
)


def xml_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    media_type = ctx.case.media_type

    assert media_type is not None

    raw_schema = ctx.case.operation.get_raw_payload_schema(media_type)
    resolved_schema = ctx.case.operation.get_resolved_payload_schema(media_type)

    return serialize_xml(value, raw_schema, resolved_schema)


SERIALIZERS_REGISTRY.register(
    [RequestsTransport, ASGITransport, WSGITransport], ["application/xml", "text/xml"], xml_serializer
)


def urlencoded_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    return {"data": value}


SERIALIZERS_REGISTRY.register(
    [RequestsTransport, ASGITransport, WSGITransport], ["application/x-www-form-urlencoded"], urlencoded_serializer
)


def text_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        return {"data": value}
    return {
        "data": str(value).encode("utf8")
    }  # TODO: check if not collapse with schemathesis.transport.wsgi.text_serializer


SERIALIZERS_REGISTRY.register([RequestsTransport, ASGITransport], ["text/plain"], text_serializer)


def binary_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    return {"data": serialize_binary(value)}


SERIALIZERS_REGISTRY.register(
    [RequestsTransport, ASGITransport, WSGITransport], ["application/octet-stream"], binary_serializer
)
