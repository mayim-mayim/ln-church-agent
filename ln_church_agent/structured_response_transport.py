"""V3 closed routes on the existing pinned, quota-aware Venue exchange."""
from __future__ import annotations
from functools import wraps
from urllib.parse import urlencode
import math
import time

from . import structured_response_contract as c
from .access_quota import AccessQuotaError
from .task_journal import JournalError,JournalPersistenceError
from .immediate_visit_transport import ImmediateVisitTransport, ImmediateVisitRawResponse, ImmediateVisitError, MAXIMUM_JSON_BYTES, MAXIMUM_RESPONSE_HEADER_BYTES


class StructuredResponseError(Exception):
    def __init__(self,code,*,status_code=None,request_bytes_sent=None,journal_handle=None):
        self.code=code if code in {'CLIENT_CLOSED','TRANSPORT_CLOSED','TRANSPORT_ERROR','RESPONSE_INVALID','RESPONSE_BINDING_INVALID','TIMEOUT','CLAIM_OUTCOME_UNKNOWN','API_ERROR','UNSUPPORTED_TUPLE'} else 'TRANSPORT_ERROR'
        self.status_code=status_code
        self.request_bytes_sent=request_bytes_sent
        self.journal_handle=journal_handle
        super().__init__(self.code)


class StructuredResponseAPIError(StructuredResponseError):
    def __init__(self,code,*,status_code,retry_after_seconds=None):
        allowed={'invalid_request','payload_too_large','invalid_structure','invalid_claim_token','not_found','task_not_found','idempotency_conflict','terms_confirmation_required','capacity_unavailable','participation_ineligible','once_per_offer_consumed','prerequisites_pending','claim_expired','snapshot_unavailable','rate_limited','temporarily_unavailable','listing_ended','active_claim_exists','report_already_accepted','report_conflict'}
        self.public_error_code=code if code in allowed else 'invalid_response'
        self.retry_after_seconds=retry_after_seconds
        super().__init__('API_ERROR',status_code=status_code,request_bytes_sent=True)


def public_boundary(f):
    @wraps(f)
    def wrapped(*args,**kwargs):
        failed=None
        try:
            return f(*args,**kwargs)
        except AccessQuotaError as e:
            failed=e.detached()
        except JournalPersistenceError:
            failed=JournalPersistenceError()
        except JournalError as e:
            failed=JournalError(e.code)
        except StructuredResponseAPIError as e:
            failed=StructuredResponseAPIError(e.public_error_code,status_code=e.status_code,retry_after_seconds=e.retry_after_seconds)
        except StructuredResponseError as e:
            failed=StructuredResponseError(e.code,status_code=e.status_code,request_bytes_sent=e.request_bytes_sent,journal_handle=e.journal_handle)
        except ValueError:
            failed=ValueError('Invalid structured response operation.')
        except Exception:
            failed=StructuredResponseError('TRANSPORT_ERROR',request_bytes_sent=None)
        if failed is not None:
            raise failed
    return wrapped


class StructuredResponseTransport(ImmediateVisitTransport):
    def __init__(self,*,definition_version=c.TASK_DEFINITION_VERSION,**kwargs):
        self.definition_version=c.validate_version(definition_version)
        super().__init__(version='v3',**kwargs)

    @public_boundary
    def _once(self,method,path,*,query=None,claim_token=None,idempotency_key=None,body=b'',timeout_seconds=20.0,readonly=False,expected_statuses=(200,)):
        c.positive_bound(timeout_seconds,'timeout_seconds')
        if self._closed:
            raise StructuredResponseError('TRANSPORT_CLOSED',request_bytes_sent=False)
        if len(body)>c.MAX_REPORT_BYTES:
            raise ValueError('Request exceeds contract limit.')
        headers={'Accept':'application/json','Accept-Encoding':'identity','User-Agent':'ln-church-agent-structured-response/1.18.16'}
        if claim_token is not None:
            headers['X-LN-Task-Claim-Token']=c.validate_claim_token(claim_token)
        if idempotency_key is not None:
            headers['Idempotency-Key']=c.validate_opaque_id(idempotency_key,'idempotency_key')
        if body:
            headers['Content-Type']='application/json'
        deadline=self._monotonic()+timeout_seconds
        def send(extra,remaining):
            raw=self._exchange(method,path,query,dict(headers,**extra),body,remaining,
                **({'_deadline':deadline} if self._exchange==self._default_exchange else {}))
            if not isinstance(raw,ImmediateVisitRawResponse):
                raise StructuredResponseError('RESPONSE_INVALID',request_bytes_sent=True)
            return raw.status_code,raw.headers,raw.body
        try:
            status,response_headers,raw=self.access_quota.exchange(method=method,
                url=c.PUBLIC_API_ORIGIN+path+(('?'+query) if query else ''),headers=headers,body=body,
                send=send,deadline=deadline,clock=self._monotonic,readonly=readonly,maximum_body=MAXIMUM_JSON_BYTES)
        except (AccessQuotaError,StructuredResponseError):
            raise
        except ImmediateVisitError as e:
            raise StructuredResponseError(e.code,request_bytes_sent=e.request_bytes_sent) from None
        except Exception:
            raise StructuredResponseError('TRANSPORT_ERROR',request_bytes_sent=None) from None
        invalid=False
        try:
            if type(status) is not int or not 100<=status<=599 or sum(len(k)+len(v)+4 for k,v in response_headers.items())>MAXIMUM_RESPONSE_HEADER_BYTES:
                raise ValueError
            encodings=[v for k,v in response_headers.items() if k.lower()=='content-encoding']
            if encodings and (len(encodings)!=1 or encodings[0].strip().lower()!='identity'):
                raise ValueError
            payload=c.decode_json_object(raw,MAXIMUM_JSON_BYTES)
        except Exception:
            invalid=True
        if invalid:
            raise StructuredResponseError('RESPONSE_INVALID',request_bytes_sent=True)
        if status in expected_statuses:
            return payload
        try:
            c.validate_wire('error', payload)
        except ValueError:
            raise StructuredResponseError('RESPONSE_INVALID',status_code=status,request_bytes_sent=True) from None
        if (payload.get('schema_version')!=c.schema('task_error',c.version_of(payload)) or set(payload)-{'schema_version','code','message','request_id','field_errors','retry_after_ms','recovery'}
                or not {'schema_version','code','message','request_id'}<=set(payload)):
            raise StructuredResponseError('RESPONSE_INVALID',status_code=status,request_bytes_sent=True)
        retry=None
        values=[v for k,v in response_headers.items() if k.lower()=='retry-after']
        if values:
            try:
                retry=float(values[0])
                if len(values)!=1 or not math.isfinite(retry) or retry<0:
                    retry=None
            except (ValueError,TypeError):
                pass
        if type(payload.get('retry_after_ms')) is int and payload['retry_after_ms']>=0:
            retry=max(retry or 0,payload['retry_after_ms']/1000)
        raise StructuredResponseAPIError(payload.get('code'),status_code=status,retry_after_seconds=retry)

    def list_tasks(self,*,limit=25,cursor=None,timeout_seconds=20.0):
        c.positive_bound(limit,'limit',integer=True,maximum=100)
        params=dict(task_type=c.TASK_TYPE,task_schema_version=c.schema('agent_task',self.definition_version),limit=str(limit))
        if cursor is not None:
            params['cursor']=c.cursor(cursor)
        return self._once('GET','/api/agent/tasks',query=urlencode(params),timeout_seconds=timeout_seconds)

    def get_context(self,task_id,claim_token,*,timeout_seconds=20.0):
        return self._once('GET',c.task_detail_path(task_id)+'/context',claim_token=claim_token,timeout_seconds=timeout_seconds)

    def get_task(self,task_id,*,timeout_seconds=20.0):
        query=urlencode(dict(task_type=c.TASK_TYPE,task_schema_version=c.schema('agent_task',self.definition_version)))
        return self._once('GET',c.task_detail_path(task_id),query=query,timeout_seconds=timeout_seconds)

    def get_submission_status(self,task_id,submission_id,claim_token,*,timeout_seconds=20.0):
        return self._once('GET',c.task_status_path(task_id,submission_id),claim_token=claim_token,timeout_seconds=timeout_seconds)
