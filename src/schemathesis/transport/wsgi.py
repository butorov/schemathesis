from typing import TYPE_CHECKING, Any

from httpx import WSGITransport

from schemathesis.transport.serialization import SERIALIZERS_REGISTRY

if TYPE_CHECKING:
    from schemathesis.transport import SerializationContext


def multipart_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    return {"data": value}


SERIALIZERS_REGISTRY.register([WSGITransport], ["multipart/form-data", "multipart/mixed"], multipart_serializer)


def text_serializer(ctx: SerializationContext, value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        return {"data": value}
    return {"data": str(value)}


SERIALIZERS_REGISTRY.register([WSGITransport], ["text/plain"], text_serializer)
