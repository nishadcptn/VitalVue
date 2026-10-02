"""The gateway logs every TCP connection, including ones that never identify as a watch."""
import asyncio
import io
import logging

from app.core.config import settings
from app.devices.registry import get_type
from app.gateway.server import Gateway, preview


def run_clients(monkeypatch, payloads: list[bytes]) -> str:
    monkeypatch.setattr(settings, "GATEWAY_FIRST_FRAME_S", 0.5)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log = logging.getLogger("gateway")
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    async def main():
        gw = Gateway(None, None)                      # unidentified connections never touch the db
        dtype = get_type("bpw8_4g")
        srv = await asyncio.start_server(lambda r, w: gw.on_connect(dtype, r, w), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        async def client(payload: bytes):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            if payload:
                w.write(payload)
                await w.drain()
            await r.read()                            # until the gateway drops us
            w.close()

        await asyncio.gather(*(client(p) for p in payloads))
        srv.close()
        await srv.wait_closed()

    try:
        asyncio.run(main())
    finally:
        log.removeHandler(handler)
    return buf.getvalue()


def test_silent_connection_is_logged(monkeypatch):
    out = run_clients(monkeypatch, [b""])
    assert "CLOC BPW8 port: connection opened from 127.0.0.1:" in out
    assert "unidentified · sent nothing for 0.5s · 0 bytes, 0 frames" in out
    assert "first bytes" not in out


def test_wrong_protocol_is_logged_with_its_bytes(monkeypatch):
    out = run_clients(monkeypatch, [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"])
    assert "no valid CLOC BPW8 frame within 0.5s · 27 bytes, 0 frames" in out
    assert 'first bytes from 127.0.0.1: "GET / HTTP/1.1..Host: x...."  hex: 47 45 54 20' in out


def test_preview_trims_hex_and_masks_binary():
    p = preview(b"\x16\x03\x01" + bytes(100))
    assert p.startswith('"...')
    assert p.endswith(" …")
    assert p.count(" ") < 80
