from __future__ import annotations

import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Generator

import httpx

from schemathesis.core import NotSet
from schemathesis.core.rate_limit import ratelimit
from schemathesis.core.transport import Response
from schemathesis.generation.case import Case
from schemathesis.python import wsgi
from schemathesis.transport import BaseTransport, SerializationContext
from schemathesis.transport.prepare import normalize_base_url, prepare_body, prepare_headers, prepare_path
from schemathesis.transport.requests import REQUESTS_TRANSPORT
from schemathesis.transport.serialization import serialize_binary, serialize_json, serialize_xml, serialize_yaml


class WSGITransport(BaseTransport, httpx.WSGITransport): ...


WSGI_TRANSPORT = WSGITransport()


# @WSGI_TRANSPORT.serializer("application/json", "text/json")
# def json_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
#     return serialize_json(value)


@WSGI_TRANSPORT.serializer(
    "text/yaml", "text/x-yaml", "text/vnd.yaml", "text/yml", "application/yaml", "application/x-yaml"
)
def yaml_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
    return serialize_yaml(value)


@WSGI_TRANSPORT.serializer("multipart/form-data", "multipart/mixed")
def multipart_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
    return {"data": value}


@WSGI_TRANSPORT.serializer("application/xml", "text/xml")
def xml_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
    media_type = ctx.case.media_type

    assert media_type is not None

    raw_schema = ctx.case.operation.get_raw_payload_schema(media_type)
    resolved_schema = ctx.case.operation.get_resolved_payload_schema(media_type)

    return serialize_xml(value, raw_schema, resolved_schema)


@WSGI_TRANSPORT.serializer("application/x-www-form-urlencoded")
def urlencoded_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
    return {"data": value}


@WSGI_TRANSPORT.serializer("text/plain")
def text_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        return {"data": value}
    return {"data": str(value)}


@WSGI_TRANSPORT.serializer("application/octet-stream")
def binary_serializer(ctx: SerializationContext[Case], value: Any) -> dict[str, Any]:
    return {"data": serialize_binary(value)}
