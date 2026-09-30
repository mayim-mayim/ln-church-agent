"""New-family route adapter over the existing pinned Venue transport and quota policy."""
from __future__ import annotations
from functools import wraps
from urllib.parse import urlencode
from typing import Optional

from . import endpoint_choice_reason_contract as c
from .access_quota import AccessQuotaError
from .immediate_visit_transport import (
    ImmediateVisitTransport, ImmediateVisitRawResponse, ImmediateVisitError,
    MAXIMUM_JSON_BYTES, MAXIMUM_RESPONSE_HEADER_BYTES,
)


class EndpointChoiceError(Exception):
    def __init__(self, code, *, status_code=None, request_bytes_sent=None):
        safe = {'CLIENT_CLOSED', 'TRANSPORT_CLOSED', 'TRANSPORT_ERROR', 'RESPONSE_INVALID',
                'RESPONSE_BINDING_INVALID', 'TIMEOUT', 'CLAIM_OUTCOME_UNKNOWN', 'API_ERROR', 'REQUEST_INVALID'}
        self.code = code if code in safe else 'TRANSPORT_ERROR'
        self.status_code = status_code
        self.request_bytes_sent = request_bytes_sent
        super().__init__(self.code)


class EndpointChoiceAPIError(EndpointChoiceError):
    def __init__(self, code, *, status_code):
        codes = c.ERROR_CODES.get(status_code, set()) | c.OWNER_ERRORS.get(status_code, set())
        self.public_error_code = code if code in codes else 'invalid_response'
        super().__init__('API_ERROR', status_code=status_code, request_bytes_sent=True)


def public_boundary(function):
    @wraps(function)
    def call(*args, **kwargs):
        detached = None
        try:
            return function(*args, **kwargs)
        except AccessQuotaError as error:
            detached = error.detached()
        except EndpointChoiceAPIError as error:
            detached = EndpointChoiceAPIError(error.public_error_code, status_code=error.status_code)
        except EndpointChoiceError as error:
            detached = EndpointChoiceError(error.code, status_code=error.status_code,
                                           request_bytes_sent=error.request_bytes_sent)
        except ValueError:
            detached = ValueError('Invalid endpoint choice operation.')
        if detached is not None:
            raise detached
    return call


class EndpointChoiceTransport(ImmediateVisitTransport):
    """No target fetch, implicit signing, business retry or new quota eligibility."""

    @public_boundary
    def _once(self, method, path, *, query=None, claim_token=None, idempotency_key=None,
              body=b'', timeout_seconds=20.0, readonly=False, expected_statuses=(200,), owner=False):
        c.positive_bound(timeout_seconds, 'timeout_seconds')
        if self._closed:
            raise EndpointChoiceError('TRANSPORT_CLOSED', request_bytes_sent=False)
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
                   'User-Agent': 'ln-church-agent-endpoint-choice-reason/1.18.9'}
        if claim_token is not None:
            headers['X-LN-Task-Claim-Token'] = c.validate_claim_token(claim_token)
        if idempotency_key is not None:
            headers['Idempotency-Key'] = c.validate_opaque_id(idempotency_key, 'idempotency_key')
        if body:
            headers['Content-Type'] = 'application/json'
        deadline = self._monotonic() + timeout_seconds
        def send(extra, remaining):
            raw = self._exchange(method, path, query, dict(headers, **extra), body, remaining,
                    **({'_deadline': deadline} if self._exchange == self._default_exchange else {}))
            if not isinstance(raw, ImmediateVisitRawResponse):
                raise EndpointChoiceError('RESPONSE_INVALID', request_bytes_sent=True)
            return raw.status_code, raw.headers, raw.body
        try:
            status, response_headers, raw = self.access_quota.exchange(
                method=method, url=c.PUBLIC_API_ORIGIN + path + (('?' + query) if query else ''),
                headers=headers, body=body, send=send, deadline=deadline,
                clock=self._monotonic, readonly=readonly, maximum_body=MAXIMUM_JSON_BYTES)
        except AccessQuotaError:
            raise
        except ImmediateVisitError as error:
            raise EndpointChoiceError(error.code, request_bytes_sent=error.request_bytes_sent) from None
        except EndpointChoiceError:
            raise
        except Exception:
            raise EndpointChoiceError('TRANSPORT_ERROR', request_bytes_sent=None) from None
        try:
            if type(status) is not int or sum(len(k) + len(v) + 4 for k, v in response_headers.items()) > MAXIMUM_RESPONSE_HEADER_BYTES:
                raise ValueError
            encodings = [v for k, v in response_headers.items() if k.lower() == 'content-encoding']
            if encodings and (len(encodings) != 1 or encodings[0].strip().lower() != 'identity'):
                raise ValueError
            payload = c.decode_json_object(raw, MAXIMUM_JSON_BYTES)
        except Exception:
            raise EndpointChoiceError('RESPONSE_INVALID', request_bytes_sent=True) from None
        if status in expected_statuses:
            return payload
        codes = c.OWNER_ERRORS if owner else c.ERROR_CODES
        error_schema = 'ln_church.offer_results_error.v1' if owner else c.schema('task_error')
        if (set(payload) == {'schema_version', 'code', 'message', 'request_id'}
                and payload['schema_version'] == error_schema and payload['code'] in codes.get(status, set())
                and type(payload['message']) is str and type(payload['request_id']) is str):
            code = payload['code']
            payload.clear()
            if status == 503:
                raise EndpointChoiceError('TRANSPORT_ERROR', status_code=status, request_bytes_sent=True)
            raise EndpointChoiceAPIError(code, status_code=status)
        raise EndpointChoiceError('RESPONSE_INVALID', status_code=status, request_bytes_sent=True)

    def list_tasks(self, *, limit=25, cursor=None, timeout_seconds=20.0):
        c.positive_bound(limit, 'limit', integer=True, maximum=100)
        params = dict(task_type=c.TASK_TYPE, task_schema_version=c.TASK_SCHEMA_VERSION, limit=str(limit))
        if cursor is not None:
            params['cursor'] = c.cursor(cursor)
        return self._once('GET', '/api/agent/tasks', query=urlencode(params), timeout_seconds=timeout_seconds)

    def public_results(self, task_id, *, limit=20, cursor=None, timeout_seconds=20.0):
        c.positive_bound(limit, 'limit', integer=True, maximum=50)
        params = {'limit': str(limit)}
        if cursor is not None: params['cursor'] = c.cursor(cursor)
        return self._once('GET', c.task_detail_path(task_id) + '/results', query=urlencode(params), timeout_seconds=timeout_seconds)

    def get_submission_status(self, task_id, submission_id, claim_token, *, timeout_seconds=20.0):
        return self._once('GET', c.task_status_path(task_id, submission_id),
                          claim_token=claim_token, timeout_seconds=timeout_seconds)

    def results_challenge(self, task_id, payer, *, timeout_seconds=20.0):
        body = c.canonical_bytes(dict(schema_version='ln_church.offer_results_challenge_request.v1',
                                      task_id=c.validate_task_id(task_id), payer=c.address(payer)))
        return self._once('POST', '/api/agent/task-offer-results/challenge', body=body,
                          timeout_seconds=timeout_seconds, owner=True)

    def results_read(self, body, *, timeout_seconds=20.0):
        return self._once('POST', '/api/agent/task-offer-results/read', body=body,
                          timeout_seconds=timeout_seconds, owner=True)
