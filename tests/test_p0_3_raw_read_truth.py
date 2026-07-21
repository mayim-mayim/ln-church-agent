"""Production-shaped failure classification tests for streamed Inspect reads.

The tests use public exception classes shared by urllib3 1.26 and 2.x.  They
remain entirely offline: the ``requests.Response`` is real, while its raw body
is an in-memory object that raises the selected read failure.
"""

import socket
import ssl

import pytest
import requests
import urllib3

from ln_church_agent import inspect_transport as transport


RAW_FAILURE_MARKER = "DUMMY_RAW_READ_FAILURE_P0_3"


class _RaisingRaw:
    """Minimal urllib3-shaped raw stream with observable resource release."""

    def __init__(self, failure):
        self.decode_content = True
        self.failure = failure
        self.read_calls = []
        self.closed = False
        self.released = False

    def read(self, amount, decode_content=False):
        self.read_calls.append((amount, decode_content))
        raise self.failure

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


def _response_raising(failure):
    response = requests.Response()
    response.status_code = 200
    response.headers = {
        "Content-Encoding": "identity",
        "Content-Type": "application/octet-stream",
    }
    response.raw = _RaisingRaw(failure)
    return response


@pytest.mark.parametrize(
    "failure_factory,expected_code",
    [
        pytest.param(
            lambda: urllib3.exceptions.ReadTimeoutError(
                None,
                None,
                RAW_FAILURE_MARKER,
            ),
            "transport_timeout",
            id="urllib3-read-timeout",
        ),
        pytest.param(
            lambda: urllib3.exceptions.SSLError(RAW_FAILURE_MARKER),
            "tls_verification_failed",
            id="urllib3-tls",
        ),
        pytest.param(
            lambda: requests.exceptions.Timeout(RAW_FAILURE_MARKER),
            "transport_timeout",
            id="requests-timeout",
        ),
        pytest.param(
            lambda: requests.exceptions.SSLError(RAW_FAILURE_MARKER),
            "tls_verification_failed",
            id="requests-tls",
        ),
        pytest.param(
            lambda: socket.timeout(RAW_FAILURE_MARKER),
            "transport_timeout",
            id="stdlib-socket-timeout",
        ),
        pytest.param(
            lambda: ssl.SSLError(1, RAW_FAILURE_MARKER),
            "tls_verification_failed",
            id="stdlib-tls",
        ),
        pytest.param(
            lambda: urllib3.exceptions.NewConnectionError(
                None,
                RAW_FAILURE_MARKER,
            ),
            "network_error",
            id="urllib3-new-connection-is-not-a-timeout",
        ),
        pytest.param(
            lambda: urllib3.exceptions.ProtocolError(RAW_FAILURE_MARKER),
            "network_error",
            id="urllib3-protocol-error",
        ),
    ],
)
def test_raw_read_failures_have_fixed_truth_and_release_resources(
    failure_factory,
    expected_code,
):
    response = _response_raising(failure_factory())

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(response)

    error = caught.value
    serialized_error = repr(
        {
            "stage": error.stage,
            "code": error.code,
            "message": str(error),
            "public_url": error.public_url,
        }
    )

    assert error.stage == "transport"
    assert error.code == expected_code
    assert str(error) == expected_code
    assert RAW_FAILURE_MARKER not in serialized_error
    assert response.raw.read_calls == [(64 * 1024, False)]
    assert response.raw.decode_content is False
    assert response.raw.closed is True
    assert response.raw.released is True


class _LowLevelFailingBody:
    """File-like body used by a real urllib3 ``HTTPResponse``."""

    def __init__(self, failure):
        self.failure = failure
        self.closed = False

    def read(self, _amount=-1):
        raise self.failure

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    "failure_factory,expected_code",
    [
        pytest.param(
            lambda: socket.timeout(RAW_FAILURE_MARKER),
            "transport_timeout",
            id="urllib3-wraps-socket-timeout",
        ),
        pytest.param(
            lambda: ssl.SSLError(1, RAW_FAILURE_MARKER),
            "tls_verification_failed",
            id="urllib3-wraps-stdlib-tls",
        ),
    ],
)
def test_real_urllib3_http_response_preserves_raw_read_failure_truth(
    failure_factory,
    expected_code,
):
    body = _LowLevelFailingBody(failure_factory())
    raw = urllib3.response.HTTPResponse(
        body=body,
        headers={"Content-Encoding": "identity"},
        preload_content=False,
        decode_content=False,
    )
    response = requests.Response()
    response.status_code = 200
    response.headers = {"Content-Encoding": "identity"}
    response.raw = raw

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(response)

    error = caught.value
    assert error.stage == "transport"
    assert error.code == expected_code
    assert str(error) == expected_code
    assert RAW_FAILURE_MARKER not in repr(error)
    assert body.closed is True
    assert raw.closed is True
