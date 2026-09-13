"""Offline Inspect responses and transport capture shared by boundary tests."""

import json
from ln_church_agent import inspect_transport as transport

PUBLIC_V4 = "8.8.8.8"


class _FakeRaw:
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.read_calls = []
        self.decode_content = True

    def read(self, amount, decode_content=False):
        self.read_calls.append((amount, decode_content))
        if not self._chunks:
            return b""
        outcome = self._chunks[0]
        if isinstance(outcome, BaseException):
            self._chunks.pop(0)
            raise outcome
        if len(outcome) <= amount:
            return self._chunks.pop(0)
        self._chunks[0] = outcome[amount:]
        return outcome[:amount]


class _FakeResponse:
    def __init__(
        self,
        status_code=200,
        *,
        headers=None,
        content=b"",
        url="https://public.example/",
        chunks=None,
    ):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.url = url
        self._content = content
        self._content_consumed = True
        self._chunks = list(chunks) if chunks is not None else [content]
        self.raw = _FakeRaw(self._chunks)
        self.closed = False

    @property
    def content(self):
        return self._content

    def json(self):
        return json.loads(self._content.decode("utf-8"))

    def iter_content(self, chunk_size=1, decode_unicode=False):
        del chunk_size, decode_unicode
        yield from self._chunks

    def close(self):
        self.closed = True


def _public_resolver(monkeypatch, addresses=(PUBLIC_V4,)):
    calls = []

    def resolve(host, port):
        calls.append((host, port))
        return tuple(addresses)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    return calls


def _fake_exchange(monkeypatch, responses):
    """Install a sequenced private transport seam and return captured calls."""

    calls = []
    queue = list(responses)

    def exchange(target, address, method, timeout, body=None):
        calls.append(
            {
                "target": target,
                "address": address,
                "method": method,
                "timeout": timeout,
                "body": body,
            }
        )
        if not queue:
            raise AssertionError("unexpected transport call")
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        outcome.url = target.url
        return outcome

    monkeypatch.setattr(transport, "_exchange_once", exchange)
    return calls
