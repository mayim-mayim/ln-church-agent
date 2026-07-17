"""Shared production-shaped P0-2 contract fixture helpers."""

import json
from pathlib import Path

import requests


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "agent-server-l402-contract-v1.json"
)


def load_contract_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def contract_response(fixture, *, status=402, body=None, headers=None):
    request = fixture["request"]
    response = fixture["response"]
    prepared = requests.Request(
        request["method"], request["url"], headers=request["headers"]
    ).prepare()
    result = requests.Response()
    result.status_code = status
    result.headers.update(
        response["headers"] if headers is None else headers
    )
    result._content = json.dumps(
        response["body"] if body is None else body
    ).encode("utf-8")
    result.request = prepared
    result.url = request["url"]
    return result


def success_response(fixture, body=None):
    return contract_response(
        fixture,
        status=200,
        body={"status": "ok"} if body is None else body,
        headers={},
    )


def configure_contract_clock(client, fixture):
    client._clock = lambda: fixture["clock_unix_seconds"]
    return client
