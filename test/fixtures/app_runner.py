from __future__ import annotations

import asyncio
import socket
import threading
from time import sleep
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Callable

import pytest
from aiohttp import web

if TYPE_CHECKING:
    from flask import Flask


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(target: Callable, port: int | None = None, timeout: float = 0.05, **kwargs: Any) -> int:
    """Start a thread with the given aiohttp application."""
    if port is None:
        port = unused_port()
    server_thread = threading.Thread(target=target, kwargs={"port": port, **kwargs})
    server_thread.daemon = True
    server_thread.start()
    sleep(timeout)
    return port


def _run_server(app: web.Application, port: int) -> None:
    """Run the given app on the given port.

    Intended to be called as a target for a separate thread.
    NOTE. `aiohttp.web.run_app` works only in the main thread and can't be used here (or maybe can we some tuning)
    """
    # Set a loop for a new thread (there is no by default for non-main threads)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runner = web.AppRunner(app)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, "127.0.0.1", port)
    loop.run_until_complete(site.start())
    loop.run_forever()


def run_aiohttp_app(app: web.Application, port: int | None = None, timeout: float = 0.05) -> int:
    """Start a thread with the given aiohttp application."""
    return run(_run_server, app=app, port=port, timeout=timeout)


def run_flask_app(app: Flask, port: int | None = None, timeout: float = 0.05) -> int:
    """Start a thread with the given aiohttp application."""
    return run(app.run, port=port, timeout=timeout)


@pytest.fixture(scope="session")
def app_runner():
    return SimpleNamespace(run_flask_app=run_flask_app, run_aiohttp_app=run_aiohttp_app)
