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
    if value not in ("v1", "v2", "v3"):
        raise ValueError("Unsupported immediate visit version.")
    return value


def version_of(value):
    return validate_version(value.profile_id.rsplit(".", 1)[-1])


def claim_schema(version):
    return ("ln_church.agent_task_claim_request.v1" if validate_version(version) == "v1"
            else "ln_church.agent_task_claim_request.immediate_visit." + version)


def validate_tuple(value):
    version = version_of(value)
    if value.task_type != "immediate_http_visit." + version:
        raise ValueError("Cross-version immediate visit tuple.")
    if value.schema_version.rsplit(".", 1)[-1] != version:
        raise ValueError("Cross-version immediate visit schema.")
    if hasattr(value, "definition_version") and value.definition_version != {"v1": "1.0.0", "v2": "2.0.0", "v3": "3.0.0"}[version]:
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
    if profile_id not in ("immediate_visit_utf8.v2", "immediate_visit_utf8.v3"):
        raise ValueError("Unsupported immediate visit profile.")
    version = profile_id.rsplit(".", 1)[-1]
    profile = decode_json_object(load_pack(version)["profile.json"], 2097152)
    if (profile["profile_id"] != profile_id or profile["task_type"] != "immediate_http_visit." + version
            or profile["request_headers"] != {"Accept": "*/*", "Accept-Encoding": "identity"}
            or set(profile["user_agents"]) != {"agent", "reference"}):
        raise ValueError("Invalid Immediate v2 role profile.")
    return profile["user_agents"]["agent"]


# Pinned to Hondo 90b06a6c58ec76b09f7adb9b430ce34f6d2a0b71.
V3_PACK_SHA256 = {'SKILL.md': 'b136f2f9b597285f3b9478ef02a72df9ab9d620c747c220450fa0725e48b939f',
 'abandon-request.schema.json': 'ebe360f48228a4b6a80c07ec1eabf852f683eec30b1434aa45688268e75ab279',
 'abandon-response.schema.json': '883ad6b64b395604ea92cf915dbf11657e9c60a32faa0c859b69a328ef358aac',
 'claim-request.schema.json': '2533eb726304c7f835ee53948b13a4a376a9c005cdc94b670058e4fd14417cd0',
 'claim.schema.json': '699fdea367bdd2706d5d6006c1fe5010d6f03b39da6f93f33a9e05037e0d3fa5',
 'definition.json': '3a3c8f18591c0a83b1fd15cb62e6928a86822d4d1d5c137efacd2f92249efc91',
 'error.schema.json': '1214e0b79dbeb97346742a1fbb987322049aaee67b46d281c1c3437cb896f424',
 'execution-page.schema.json': '694625133ae9bbaca3a14aa614c3a38e3243943ce3adcf273ba89654ec5f81ca',
 'manifest.json': 'e7642e2bc6540d137bfa3e27a9339f02ba460a8a9254c8572b3ac2f91bdcda4c',
 'observation.schema.json': '32c22e00d9e91487d20b1d4ef48cef3c26fcda76e43d99e25c4847748092cb64',
 'page.schema.json': '8aff4cbebd038d28f27be09b4d461c7e1e57091660494dba79d432768a7c0a36',
 'profile-fixtures.json': '8f76be41390c751df0008dec8722197af026a3169675b58d453ed489bae551a7',
 'profile.json': '68a06d75c6bf275494872a193fa8a5e6046ac5d1daec0575b3f84ff14e411919',
 'receipt.schema.json': 'bf7bc478051ed479a57f3e13fb57f237e4b03564b987540cbeff098e8f38a0e2',
 'registration-result.schema.json': 'fb1b6f8489476518562c758a2c0de556a5223ecbdec891e7176637feb79afb55',
 'registration.schema.json': 'e0702f59bde8ad37fea02fb23406a7b0a2deae7b7c39908a83aa80bc7255af16',
 'requester-registration/SKILL.md': 'ec669f9e6d4de23e045a33471b7804c35715c88397dd451248129ab1c2ac4ed8',
 'result.schema.json': 'd1af58c98d6f2466d1425931a7b3d5369f1b9a9fdb79fbcc1fc3973854002048',
 'submission.schema.json': '758463460a14e4223719d7deea95967d616756bf18cac0340752be5e9f83b267',
 'summary.schema.json': 'd0f88260ccf1423bbccb3efcd9a2de1126c4b95f59a8f8afedfa7aaf8b1fb255',
 'task.schema.json': '9f08fb64d1dd8710d179595c0185683e9a6db484eadea822b458cd2ada401cea',
 'wire-fixtures.json': 'bb38adbf498c85e612c976f2c7bfe12ebe3d60030b9a9ac00760800f2844f15f'}

def load_pack(version):
    validate_version(version)
    if version == 'v2':
        return load_v2_pack()
    if version != 'v3' or not V3_PACK_SHA256:
        raise ValueError('Fixed Immediate v3 contract pack has not been received.')
    root = Path(__file__).parent / 'contracts' / 'v183-immediate-visit-v3'
    if {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} != set(V3_PACK_SHA256):
        raise ValueError('Invalid Immediate v3 contract pack.')
    resources = {name: (root / name).read_bytes() for name in V3_PACK_SHA256}
    if any(hashlib.sha256(raw).hexdigest() != V3_PACK_SHA256[name] for name, raw in resources.items()):
        raise ValueError('Invalid Immediate v3 contract pack.')
    from .immediate_visit_profile import jcs_bytes
    manifest = decode_json_object(resources['manifest.json'], 2097152)
    if (manifest['task_type'] != 'immediate_http_visit.v3'
            or manifest['task_definition_version'] != '3.0.0'
            or manifest['task_definition_digest'] != hashlib.sha256(jcs_bytes(manifest['descriptor'])).hexdigest()):
        raise ValueError('Invalid Immediate v3 descriptor.')
    return resources
