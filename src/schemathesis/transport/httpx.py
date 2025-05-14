from __future__ import annotations

from typing import TYPE_CHECKING, Any

from schemathesis.core.transport import Response
from schemathesis.transport import BaseTransport

if TYPE_CHECKING:
    import httpx

    from schemathesis.generation.case import Case


class HttpxTransport(BaseTransport["Case", Response, "httpx.Client"]):
    def send(self, case: Case, *, session: httpx.Client | None = None, **kwargs: Any) -> Response: ...

    async def send_async(self, case: Case, *, session: httpx.AsyncClient | None = None, **kwargs: Any) -> Response: ...


HTTPX_TRANSPORT = HttpxTransport()
