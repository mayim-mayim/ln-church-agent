"""DC-fixed external correction; never modifies or replaces the 3.0 pack."""
from pathlib import Path
import hashlib

DIRECTORY = 'v1816-structured-response-v3_0-correction-c1'
DIGEST = '497eeff577e6916c4ccc5e612ac20aca32688be29bc50f43aa6310ebed70cf0d'
MANIFEST_SHA256 = '8c59dede070fb6979a6e90d80bee7c674ccd938c2268608c0eb89f92774f54cf'
PUBLIC_ROOT = '/agent-task-spec-corrections/structured_response.v3/3.0.0/c1/'
SOURCE_COMMIT = '68d93c859b46f9e4b76c34743d44f4dc0488fbe6'


def load_correction():
    from . import structured_response_contract as c
    root = Path(__file__).parent / 'contracts' / DIRECTORY
    raw = (root / 'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError('Invalid Structured correction manifest bytes.')
    manifest = c.decode_json_object(raw, 2097152)
    descriptor = manifest['descriptor']
    if manifest['correction_digest'] != DIGEST or c.digest(descriptor) != DIGEST:
        raise ValueError('Invalid Structured correction digest.')
    target = descriptor['target']
    expected = dict(task_type=c.TASK_TYPE, task_definition_version='3.0.0',
                    task_schema_version=c.TASK_SCHEMA_VERSION,
                    completion_schema_version=c.schema('task_completion'),
                    task_definition_digest=c.PACK_SOURCE['task_definition_digest'],
                    manifest_sha256=c.PACK_SHA256['manifest.json'],
                    completion_schema_sha256=c.PACK_SHA256['completion.schema.json'],
                    question_bank_sha256=c.PACK_SHA256['question-bank.json'])
    if target != expected:
        raise ValueError('Invalid Structured correction target.')
    resources = {'manifest.json': raw}
    for item in descriptor['resources']:
        if not item['path'].startswith(PUBLIC_ROOT):
            raise ValueError('Invalid Structured correction resource path.')
        name = item['path'][len(PUBLIC_ROOT):]
        if not name or '/' in name or name in resources or name in ('.', '..'):
            raise ValueError('Invalid Structured correction inventory.')
        data = (root / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Invalid Structured correction resource bytes.')
        resources[name] = data
    if set(resources) != {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}:
        raise ValueError('Invalid Structured correction inventory.')
    return dict(manifest=manifest, resources=resources)
