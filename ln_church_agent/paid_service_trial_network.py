"""Version-selected paid request and independent read-only Base RPC boundaries."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import socket
import ssl
import time
from urllib.parse import urlsplit
from typing import Any

from . import paid_service_trial_contract as c
from .paid_service_trial_models import PurchaseTerms
from .network_fetch import (
    _canonical_https_url, _resolve_public_addresses, _system_resolver,
    _sockaddr, _same_peer, _set_timeout, _remaining, _ImmediateVisitReader,
    _parse_immediate_visit_head, _visit_chunk_size, _visit_trailers,
)


@dataclass(frozen=True)
class PaidTrialHTTPResponse:
    status_code: Any
    headers: Any = field(repr=False)
    body: bytes = field(repr=False)
    complete: bool = True


def _read_body(reader: Any, headers: Any, status: int, maximum: int) -> bytes:
    lengths=[v.strip() for k,v in headers if k=='content-length']
    transfers=[v.strip().lower() for k,v in headers if k=='transfer-encoding']
    if transfers and (lengths or transfers!=['chunked']):
        raise ValueError
    if lengths:
        if any(not re.fullmatch('[0-9]{1,16}',v) for v in lengths) or len({int(v) for v in lengths})!=1 or int(lengths[0])>maximum:
            raise ValueError
    if status in {204,205,304}:
        return b''
    if transfers:
        result=bytearray()
        while True:
            size=_visit_chunk_size(reader,maximum-len(result))
            if size==0:
                _visit_trailers(reader);return bytes(result)
            result.extend(reader.read_exact(size))
            if reader.read_exact(2)!=b'\r\n':
                raise ValueError
    return reader.read_exact(int(lengths[0])) if lengths else reader.read_to_eof(maximum)


class PaidServiceTrialHTTPS:
    """Fresh all-address DNS validation, one pinned TLS connection, no replay."""
    def __init__(self, *, resolver: Any=_system_resolver, socket_factory: Any=socket.socket,
                 ssl_context_factory: Any=ssl.create_default_context, monotonic: Any=time.monotonic) -> None:
        self._resolver=resolver;self._socket_factory=socket_factory
        self._ssl_context_factory=ssl_context_factory;self._monotonic=monotonic

    def __repr__(self) -> str:
        return 'PaidServiceTrialHTTPS()'

    def fetch(self, endpoint: Any, *, payment_signature: Any=None) -> PaidTrialHTTPResponse:
        if isinstance(endpoint, dict):
            request = c.validate_request(endpoint)
            url = request['url']; method = request['method']
            body = request['body'].encode('utf-8') if method=='POST' else b''
        else:
            url = c.endpoint(endpoint); method = 'GET'; body = b''
        if payment_signature is not None and (not isinstance(payment_signature,str) or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',payment_signature) or len(payment_signature)>16384):
            raise ValueError('Invalid payment header.')
        return self._request(url, method=method, body=body, payment_signature=payment_signature,
                             total=20.0 if payment_signature else 12.0,
                             head=18.0 if payment_signature else 10.0, maximum=c.MAX_BODY_BYTES)

    def _request(self,url: str,*,method: str,body: bytes,payment_signature: Any,
                 total: float,head: float,maximum: int) -> PaidTrialHTTPResponse:
        raw=None;tls=None;status=None;headers=()
        try:
            parsed=_canonical_https_url(url)
            host=parsed.hostname
            # URL validation/pinning never forwards userinfo, cookies or proxies.
            start=self._monotonic();deadline=start+total;connect_deadline=min(deadline,start+3.0)
            addresses=_resolve_public_addresses(host,resolver=self._resolver,timeout=_remaining(connect_deadline,self._monotonic))
            pinned=addresses[0];family,target=_sockaddr(pinned)
            raw=self._socket_factory(family,socket.SOCK_STREAM,socket.IPPROTO_TCP)
            _set_timeout(raw,3.0,connect_deadline,self._monotonic);raw.connect(target)
            if not _same_peer(pinned,raw.getpeername()):
                raise ValueError
            context=self._ssl_context_factory()
            if context.verify_mode!=ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
            _set_timeout(raw,3.0,connect_deadline,self._monotonic)
            tls=context.wrap_socket(raw,server_hostname=host,suppress_ragged_eofs=False);raw=None
            if not _same_peer(pinned,tls.getpeername()):
                raise ValueError
            _remaining(connect_deadline,self._monotonic)
            target=url[len('https://')+len(urlsplit(url).netloc):]
            lines=[method+' '+target+' HTTP/1.1','Host: '+host,
                   'User-Agent: LNChurch-Paid-Trial/1.0','Accept: */*','Accept-Encoding: identity','Connection: close']
            if payment_signature:
                lines.append('PAYMENT-SIGNATURE: '+payment_signature)
            if method=='POST':
                lines.extend(['Content-Type: application/json','Content-Length: '+str(len(body))])
            _set_timeout(tls,total,deadline,self._monotonic)
            tls.sendall(('\r\n'.join(lines)+'\r\n\r\n').encode('ascii')+body)
            reader=_ImmediateVisitReader(tls,deadline=deadline,head_deadline=min(deadline,start+head),monotonic=self._monotonic)
            size=0
            while True:
                raw_head=reader.read_head(c.MAX_HEADER_BYTES-size);size+=len(raw_head)
                status,headers=_parse_immediate_visit_head(raw_head)
                if status==101:
                    raise ValueError
                if status>=200:
                    break
            encodings=[v.strip().lower() for k,v in headers if k=='content-encoding']
            if any(v!='identity' for v in encodings):
                raise ValueError
            content=_read_body(reader,headers,status,maximum)
            _remaining(deadline,self._monotonic)
            return PaidTrialHTTPResponse(status,headers,content,True)
        except Exception:
            # Preserve a bounded locator even if the seller body failed. No raw
            # exception or body is retained and no transport retry is possible.
            return PaidTrialHTTPResponse(status,headers,b'',False)
        finally:
            for stream in (tls,raw):
                if stream is not None:
                    try:stream.close()
                    except Exception:pass


def normalize_requirements(value: Any) -> PurchaseTerms:
    if type(value) is not dict:
        raise ValueError('Unsupported purchase terms.')
    req=dict(value)
    # Aliases/mechanisms cannot silently contradict the recognized fields.
    aliases={'chainId':8453,'maxAmountRequired':req.get('amount'),'recipient':req.get('payTo'),
             'tokenAddress':req.get('asset'),'authorization_method':'EIP-3009','x402_version':2,
             'assetTransferMethod':'eip3009'}
    for key,expected in aliases.items():
        if key in req and req[key]!=expected:
            raise ValueError('Unsupported purchase terms.')
    extra=req.get('extra',{})
    if type(extra) is not dict or any('permit' in str(k).lower() or '7710' in str(k) for k in list(req)+list(extra)):
        raise ValueError('Unsupported purchase terms.')
    if any(key in req for key in ('extensions','authorization','paymentRequirements')):
        raise ValueError('Unsupported purchase terms.')
    if any(key in extra for key in ('scheme','network','asset','amount','payTo','maxTimeoutSeconds','chainId','tokenAddress')):
        raise ValueError('Unsupported purchase terms.')
    selected={k:req[k] for k in ('scheme','network','asset','amount','payTo','maxTimeoutSeconds')}
    selected['asset']=c.address(selected['asset'])
    selected['extra']={k:extra[k] for k in ('name','version','assetTransferMethod') if k in extra}
    selected['extra'].setdefault('name','USD Coin');selected['extra'].setdefault('version','2')
    return PurchaseTerms(x402_version=2,authorization_method='EIP-3009',requirements=selected)


@dataclass(frozen=True, repr=False)
class _CurrentTerms:
    terms: PurchaseTerms
    asset: str
    pay_to: str


def _current_terms_context(response: PaidTrialHTTPResponse, selected: PurchaseTerms) -> _CurrentTerms:
    if response.status_code!=402 or not response.complete or len(response.body)>c.MAX_BODY_BYTES:
        raise ValueError('Supported complete 402 requirements required.')
    headers=list(response.headers)
    if sum(len(k.encode('latin1'))+len(v.encode('latin1'))+4 for k,v in headers)>c.MAX_HEADER_BYTES:
        raise ValueError('Invalid requirements headers.')
    values=[v for k,v in headers if k.lower()=='payment-required']
    if len(set(values))>1:
        raise ValueError('Conflicting requirements.')
    header=c.decode_base64_object(values[0]) if values else None
    body=None
    if response.body:
        content_types=[v.split(';',1)[0].strip().lower() for k,v in headers if k.lower()=='content-type']
        is_json=any(v=='application/json' or v.endswith('+json') for v in content_types)
        if header is None or is_json or response.body.lstrip().startswith(b'{'):
            body=c.decode_json_object(response.body,c.MAX_BODY_BYTES)
            # A complete v2 header may accompany an unrelated bounded error
            # body. Recognized envelope fields must still agree.
            if header is not None and not {'x402Version','accepts'}.intersection(body):
                body=None
    def candidates(data: Any) -> list:
        if type(data) is not dict or type(data.get('x402Version')) is not int or data['x402Version']!=2 or type(data.get('accepts')) is not list:
            raise ValueError('Unsupported purchase terms.')
        if 'extensions' in data and data['extensions']:
            raise ValueError('Unsupported purchase terms.')
        result=[]
        for raw in data['accepts']:
            try:
                normalized=normalize_requirements(raw).model_dump(mode='json')
                if not any(item[0]==normalized for item in result):
                    result.append((normalized, raw['asset'], raw['payTo']))
            except (ValueError,KeyError,TypeError):
                continue
        return result
    a=candidates(header) if header is not None else None
    b=candidates(body) if body is not None else None
    if a is not None and b is not None and [x[0] for x in a]!=[x[0] for x in b]:
        raise ValueError('Conflicting requirements.')
    options=a if a is not None else b
    for normalized,asset,pay_to in options or []:
        if normalized==selected.model_dump(mode='json'):
            return _CurrentTerms(selected,asset,pay_to)
    raise ValueError('Purchase terms changed or unsupported.')


def current_terms(response: PaidTrialHTTPResponse, selected: PurchaseTerms) -> PurchaseTerms:
    return _current_terms_context(response,selected).terms


def _quantity(value: Any) -> int:
    if not isinstance(value,str) or not re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)',value):
        raise ValueError
    return int(value,16)


def sealed_timestamp(block: Any) -> int:
    if type(block) is not dict:
        raise ValueError
    for key in ('hash','parentHash','stateRoot','receiptsRoot','transactionsRoot'):
        c.hash32(block[key].lower())
    number=_quantity(block['number']);timestamp=_quantity(block['timestamp'])
    if (not re.fullmatch(r'0x[0-9a-fA-F]{16}',block['nonce'])
            or not re.fullmatch(r'0x[0-9a-fA-F]{512}',block['logsBloom'])
            or not 0<=_quantity(block['gasUsed'])<=_quantity(block['gasLimit'])
            or _quantity(block['gasLimit'])==0 or _quantity(block['size'])==0
            or type(block['transactions']) is not list):
        raise ValueError
    for tx in block['transactions']:
        if isinstance(tx,str):c.hash32(tx.lower())
        elif type(tx) is dict:
            c.hash32(tx['hash'].lower())
            if tx['blockHash']!=block['hash'] or _quantity(tx['blockNumber'])!=number:raise ValueError
        else:raise ValueError
    return timestamp


class BaseSealedBlockGuard:
    """Only eth_chainId and sealed eth_getBlockByNumber; no transaction RPC."""
    def __init__(self, *, base_rpc_url: str='https://mainnet.base.org', rpc: Any=None,
                 monotonic: Any=time.monotonic, sleep: Any=time.sleep) -> None:
        # Official default: https://docs.base.org/get-started/connect-to-base
        self._url=base_rpc_url.rstrip('/')+'/' if urlsplit(base_rpc_url).path=='' else base_rpc_url
        _canonical_https_url(self._url)
        self._http=PaidServiceTrialHTTPS(monotonic=monotonic)
        self._rpc=rpc or self._call;self._monotonic=monotonic;self._sleep=sleep

    def __repr__(self) -> str:
        return 'BaseSealedBlockGuard(<configured RPC>)'

    def _call(self,method: str,params: list,timeout: float) -> Any:
        body=c.canonical_bytes(dict(jsonrpc='2.0',id=1,method=method,params=params))
        response=self._http._request(self._url,method='POST',body=body,payment_signature=None,
                                     total=timeout,head=timeout,maximum=4194304)
        if response.status_code!=200 or not response.complete:
            raise ValueError
        data=c.decode_json_object(response.body,4194304)
        if data.get('jsonrpc')!='2.0' or type(data.get('id')) is not int or data['id']!=1 or 'error' in data or 'result' not in data:
            raise ValueError
        return data['result']

    def ready(self, exclusive_min: str) -> bool:
        lower=int(c.uint(exclusive_min));start=self._monotonic();deadline=start+12.0
        try:
            if _quantity(self._rpc('eth_chainId',[],min(5.0,deadline-self._monotonic())))!=8453:
                return False
            for offset in (0,1,3,6):
                wait=start+offset-self._monotonic()
                if wait>0:self._sleep(wait)
                remaining=deadline-self._monotonic()
                if remaining<=0:return False
                try:
                    block=self._rpc('eth_getBlockByNumber',['latest',False],min(5.0,remaining))
                    if self._monotonic()<deadline and sealed_timestamp(block)>lower:return True
                except Exception:pass
            return False
        except Exception:
            return False


class PaidServiceTrialTermsError(ValueError):
    """Only the API §10.6 finite reason crosses the provider boundary."""
    def __init__(self, reason: str) -> None:
        self.reason = reason if reason in c.V2_TERMS_REASONS else 'invalid_payment_required'
        super().__init__(self.reason)


def _v2_condition(raw: Any) -> dict:
    if type(raw) is not dict:
        raise PaidServiceTrialTermsError('invalid_payment_required')
    keys = ('scheme', 'network', 'asset', 'amount', 'payTo', 'maxTimeoutSeconds')
    if any(k not in raw for k in keys):
        raise PaidServiceTrialTermsError('invalid_payment_required')
    if (type(raw['scheme']) is not str or type(raw['network']) is not str
            or type(raw['maxTimeoutSeconds']) is not int
            or not 0 < raw['maxTimeoutSeconds'] <= 9007199254740991):
        raise PaidServiceTrialTermsError('invalid_payment_required')
    # Validate known values even in an unselected alternative. No dropping
    # malformed candidates to manufacture a matching header/body set.
    selected = {k:raw[k] for k in keys}
    selected['amount'] = c.uint(raw['amount'])
    selected['asset'] = c.address(raw['asset']); selected['payTo'] = c.address(raw['payTo'])
    extra = raw.get('extra', {})
    if type(extra) is not dict:
        raise PaidServiceTrialTermsError('invalid_payment_required')
    network = raw['network']
    chain = int(network.split(':')[1]) if re.fullmatch(r'eip155:[1-9][0-9]*', network) else None
    aliases = {'chainId':chain, 'chain_id':chain, 'maxAmountRequired':selected['amount'],
        'recipient':selected['payTo'], 'destination':selected['payTo'],
        'tokenAddress':selected['asset'], 'token_address':selected['asset'], 'contract':selected['asset'],
        'authorization_method':'EIP-3009', 'x402_version':2, 'x402Version':2,
        'assetTransferMethod':extra.get('assetTransferMethod','eip3009')}
    parameters = raw.get('parameters', {})
    if type(parameters) is not dict:
        raise PaidServiceTrialTermsError('invalid_payment_required')
    recognized = dict(selected, **aliases)
    addresses = {'asset','payTo','tokenAddress','token_address','contract','recipient','destination'}
    # Check recognized identities in every known condition container before
    # dropping descriptive metadata or building order-independent identities.
    for container in (raw, extra, parameters):
        for key, expected in recognized.items():
            if key not in container:
                continue
            observed = container[key]
            if key in addresses:
                if (key in {'asset','tokenAddress','token_address','contract'} and observed == 'USDC'
                        and network == c.NETWORK and selected['asset'] == c.ASSET):
                    observed = c.ASSET
                else:
                    observed = c.address(observed)
            elif key in ('chainId','chain_id') and type(observed) is str and re.fullmatch('[0-9]+', observed):
                if (observed.lstrip('0') or '0') == str(expected):
                    observed = expected
            elif key in ('amount','maxAmountRequired') and type(observed) is int:
                observed = c.uint(str(observed))
            if observed != expected or type(observed) is not type(expected):
                raise PaidServiceTrialTermsError('conflicting_payment_terms')
    if (any('permit' in k.lower() or '7710' in k for k in list(raw)+list(extra)+list(parameters))
            or any(k in container for container in (raw, parameters)
                   for k in ('extensions','authorization','paymentRequirements'))):
        raise PaidServiceTrialTermsError('unsupported_payment_profile')
    normalized_extra = {k:extra[k] for k in ('name','version','assetTransferMethod') if k in extra}
    if selected['network']==c.NETWORK and selected['asset']==c.ASSET:
        normalized_extra.setdefault('name','USD Coin'); normalized_extra.setdefault('version','2')
    if any(type(v) is not str for v in normalized_extra.values()):
        raise PaidServiceTrialTermsError('invalid_payment_required')
    selected['extra'] = normalized_extra
    return selected


def _condition_identity(value: dict) -> str:
    value = dict(value, extra=dict(value['extra']))
    value['extra'].setdefault('assetTransferMethod','eip3009')
    return c.v2_digest(value)


def _current_v2_terms(response: PaidTrialHTTPResponse, selected: PurchaseTerms, request: dict) -> _CurrentTerms:
    request = c.validate_request(request)
    selected = PurchaseTerms.model_validate(selected)
    if response.status_code != 402:
        raise PaidServiceTrialTermsError('expected_402')
    if not response.complete or type(response.body) is not bytes or len(response.body)>c.MAX_BODY_BYTES:
        raise PaidServiceTrialTermsError('invalid_payment_required')
    headers = list(response.headers.items()) if hasattr(response.headers,'items') else list(response.headers)
    if sum(len(k.encode('latin1'))+len(v.encode('latin1'))+4 for k,v in headers)>c.MAX_HEADER_BYTES:
        raise PaidServiceTrialTermsError('invalid_payment_required')
    values = [v for k,v in headers if k.lower()=='payment-required']
    if not values:
        raise PaidServiceTrialTermsError('missing_payment_required')
    if len(set(values))!=1:
        raise PaidServiceTrialTermsError('conflicting_payment_terms')
    data = c.decode_base64_object(values[0])
    def envelope(value: Any) -> dict:
        if (type(value) is not dict or type(value.get('x402Version')) is not int
                or value['x402Version']!=2 or type(value.get('resource')) is not dict
                or type(value.get('accepts')) is not list or not value['accepts']):
            raise PaidServiceTrialTermsError('invalid_payment_required')
        resource = value['resource']
        if 'url' not in resource:
            raise PaidServiceTrialTermsError('invalid_payment_required')
        if c.prepare_v2_url(resource['url'])!=request['url']:
            raise PaidServiceTrialTermsError('resource_mismatch')
        if ('x402_version' in value and (type(value['x402_version']) is not int or value['x402_version']!=2)):
            raise PaidServiceTrialTermsError('conflicting_payment_terms')
        if value.get('extensions'):
            raise PaidServiceTrialTermsError('unsupported_payment_profile')
        result = {}
        for raw in value['accepts']:
            identity = _condition_identity(_v2_condition(raw))
            # Retain only the first same-candidate pair, never the raw object.
            result.setdefault(identity,(raw['asset'],raw['payTo']))
        return result
    options = envelope(data)
    # Ordinary JSON/HTML/empty bytes are content, not another terms source.
    # First recognize markers without losing duplicate-key evidence; the strict
    # decoder below rejects duplicates only when this is a terms representation.
    import json
    marked = False
    try:
        class Pairs(list): pass
        parsed = json.loads(response.body.decode('utf-8'), object_pairs_hook=Pairs)
        marked = isinstance(parsed, Pairs) and {'x402Version','resource','accepts'} <= {k for k,v in parsed}
    except (ValueError, UnicodeError):
        pass
    if marked:
        body = c.v2_decode_json(response.body, c.MAX_BODY_BYTES)
        if envelope(body).keys()!=options.keys():
            raise PaidServiceTrialTermsError('conflicting_payment_terms')
    identity = _condition_identity(selected.requirements.wire())
    if identity not in options:
        raise PaidServiceTrialTermsError('unsupported_payment_profile')
    return _CurrentTerms(selected,*options[identity])


def _current_v2_terms_context(response: PaidTrialHTTPResponse, selected: PurchaseTerms, request: dict) -> _CurrentTerms:
    try:
        return _current_v2_terms(response, selected, request)
    except PaidServiceTrialTermsError as error:
        reason = error.reason
    except Exception:
        reason = 'invalid_payment_required'
    raise PaidServiceTrialTermsError(reason)


def current_v2_terms(response: PaidTrialHTTPResponse, selected: PurchaseTerms, request: dict) -> PurchaseTerms:
    return _current_v2_terms_context(response,selected,request).terms
