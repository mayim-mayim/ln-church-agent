"""Finite Immediate family dispatch; v2 authority arrives in the DC pack intake."""
from pathlib import Path
import hashlib

from .immediate_visit_contract import decode_json_object

# Pinned to the DC-readback Hondo c1 pack.
V2_PACK_SHA256 = {'SKILL.md': '850c4741abd3a40c33ff0bd1a7ca92279acb95191205867689225d493f514bd6',
 'abandon-request.schema.json': '6290faeb2d0c3a58c911ad939ecbfd5ca1be7bda459c9711fba70784a6bd3ad3',
 'abandon-response.schema.json': '04fc286df53bf6b9f404c3b1fd0304d99c1319ee20164bd523788a71713ddc80',
 'claim-request.schema.json': 'ef64d1a14d75c6ce1bae7d9337b87c2cd58dd342d17783369af22c3f12d51b57',
 'claim.schema.json': '932fe44b214807427986bf3aca65bb4c8f9b0638240b2ecc4ae3545c9ff1d5f0',
 'definition.json': 'e4fb5a13e1bb1bdb9eddf613502a68d62ba76c431962457742caba136233a3f5',
 'error.schema.json': '52a7bbac44135eb080f13746b6e8c7998c2969449cf69dc6562547b3721181c3',
 'execution-page.schema.json': 'c173c36750d1aafe9c4087f3e14e108e4ebdb053a2fe257645b65f8887d2f629',
 'manifest.json': '33e2db27a98c9d4539808b6556e27c0a50f68fb977296aa71f3efb0f9ffdbc54',
 'observation.schema.json': 'c9021b83718f28faeafaa9438716920e156bd12b9c94ecf8a2c5e58f12183a18',
 'page.schema.json': '15ce1c90b3bee368f7c4de78a4ad4db6cdb0c3d51d2830579e49055d35b2d2ea',
 'profile-fixtures.json': 'f089b0e4d11490c0fa5979a49225cfc0035f83df67ea887fe4d5566a13f2f2c0',
 'profile.json': '82b7e7fee02d090c4c833ea6d1c9c49a59a8ec5c2c2fc3fbe9406541d131fc40',
 'receipt.schema.json': 'cdce5650eddd0a6403cfe1e011bdf4fc1ff600e016ad5f9a884989d920edb4aa',
 'registration-result.schema.json': '34d7c9b9282e0a5d70e7427db816d047ccbebddebba13d9c0a0e1c6978874151',
 'registration.schema.json': '4902ede5cc789051ed6c062bd21be1bd7d02af0644d0f0c274811ab1ce19e7e3',
 'requester-registration/SKILL.md': '2b006fc866b4630e04089ebd20bc3adf92db7203c8777fb31aef2dc7cde09c75',
 'result.schema.json': '13dd6c8ec4a1cd31b0466e1819c31e86b6e832ada26cf9ac99d90ab978822dc0',
 'submission.schema.json': '759eebe7e44329748fbb82963b7c27e121fdd100c7ca4c1971b39f917246ea4a',
 'summary.schema.json': '755e63fd8119badfe6759c26a9362a00ae7aa315b86580596880a3d49c1852d7',
 'task.schema.json': 'e151e6a6065c0c9979348f4694fed68ce7393862a9a1a0c1d29a01fc779752db',
 'wire-fixtures.json': 'b178074d5e7b3952849c62d5fa14a07b9a2859cc0003bbdfb25435c8676865cb'}


def validate_version(value):
    if value not in ("v1", "v2"):
        raise ValueError("Unsupported immediate visit version.")
    return value


def version_of(value):
    return validate_version(value.profile_id.rsplit(".", 1)[-1])


def claim_schema(version):
    return ("ln_church.agent_task_claim_request.v1" if validate_version(version) == "v1"
            else "ln_church.agent_task_claim_request.immediate_visit.v2")


def validate_tuple(value):
    version = version_of(value)
    if value.task_type != "immediate_http_visit." + version:
        raise ValueError("Cross-version immediate visit tuple.")
    if value.schema_version.rsplit(".", 1)[-1] != version:
        raise ValueError("Cross-version immediate visit schema.")
    if hasattr(value, "definition_version") and value.definition_version != {"v1": "1.0.0", "v2": "2.0.0"}[version]:
        raise ValueError("Cross-version immediate visit definition.")


def load_v2_pack():
    if not V2_PACK_SHA256:
        raise ValueError("Fixed Immediate v2 contract pack has not been received.")
    root = Path(__file__).parent / "contracts" / "v183-immediate-visit-v2"
    if {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} != set(V2_PACK_SHA256):
        raise ValueError("Invalid Immediate v2 contract pack.")
    resources = {}
    for name, expected in V2_PACK_SHA256.items():
        raw = (root / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Invalid Immediate v2 contract pack.")
        resources[name] = raw
    from .immediate_visit_profile import jcs_bytes
    manifest = decode_json_object(resources["manifest.json"], 2097152)
    if (manifest["task_type"] != "immediate_http_visit.v2" or manifest["task_definition_version"] != "2.0.0"
            or manifest["task_definition_digest"] != hashlib.sha256(jcs_bytes(manifest["descriptor"])).hexdigest()):
        raise ValueError("Invalid Immediate v2 descriptor.")
    return resources


def agent_user_agent(profile_id):
    if profile_id == "immediate_visit_utf8.v1":
        from .network_fetch import IMMEDIATE_VISIT_USER_AGENT
        return IMMEDIATE_VISIT_USER_AGENT
    if profile_id != "immediate_visit_utf8.v2":
        raise ValueError("Unsupported immediate visit profile.")
    profile = decode_json_object(load_v2_pack()["profile.json"], 2097152)
    if (profile["profile_id"] != profile_id or profile["task_type"] != "immediate_http_visit.v2"
            or profile["request_headers"] != {"Accept": "*/*", "Accept-Encoding": "identity"}
            or set(profile["user_agents"]) != {"agent", "reference"}):
        raise ValueError("Invalid Immediate v2 role profile.")
    return profile["user_agents"]["agent"]
