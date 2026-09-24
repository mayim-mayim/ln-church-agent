"""Preservation and package checks; Backend resource verification stays explicit."""
import ast
import json
from pathlib import Path
import runpy

import pytest

from test_v1_18_5_paid_service_trial_contract import wire
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.immediate_visit_models import ImmediateVisitTask
from ln_church_agent.task_models import AgentTask

ROOT=Path(__file__).resolve().parents[1]


def test_old_strict_parsers_reject_new_family(wire):
    for model in (ImmediateVisitTask,AgentTask):
        with pytest.raises((ValueError,TypeError)):model.model_validate(wire.task)


def test_metadata_support_and_entry_points_unchanged(monkeypatch):
    import setuptools
    captured={};monkeypatch.setattr(setuptools,'setup',lambda **kwargs:captured.update(kwargs))
    monkeypatch.chdir(ROOT);runpy.run_path(str(ROOT/'setup.py'))
    assert captured['version']=='1.18.6' and captured['python_requires']=='>=3.8.1'
    assert 'contracts/v185-paid-service-trial/*' in captured['package_data']['ln_church_agent']
    assert captured['entry_points']=={'console_scripts':[
        'ln-church-agent=ln_church_agent.cli:main','lnc-agent=ln_church_agent.cli:main',
        'ln-church-agent-mcp=ln_church_agent.integrations.mcp_inspect:main']}
    manifest=json.loads((ROOT/'server.json').read_text())
    assert manifest['version']=='1.18.6' and manifest['packages'][0]['version']=='1.18.6'
    # New source retains the existing minimum Python grammar; runtime/platform
    # qualification beyond the existing support tier is not claimed.
    for path in (ROOT/'ln_church_agent').glob('paid_service_trial*.py'):
        ast.parse(path.read_text(),feature_version=(3,8))


def test_native_python_exports_resolve_without_contract_side_effects():
    from ln_church_agent import PaidServiceTrialTaskClient, PaidServiceTrialExecutor, PaidServiceTrialJournal, export_purchase_import_descriptor
    assert all(callable(x) for x in (PaidServiceTrialTaskClient,PaidServiceTrialExecutor,PaidServiceTrialJournal,export_purchase_import_descriptor))


def test_formal_backend_bundle_identity():
    root=ROOT/'ln_church_agent/contracts/v185-paid-service-trial'
    if not root.exists():
        pytest.skip('CONTRACT_BUNDLE_SYNC_PENDING: Backend candidate pack not supplied')
    bundle=c.load_contract_bundle()
    assert set(bundle['resources'])==set(c.ARTIFACT_NAMES)
    assert bundle['manifest']['task_definition_digest']==c.digest(bundle['manifest']['descriptor'])
    assert {p.name for p in root.iterdir()} == {
        'SKILL.md', 'definition.json', 'requester-guide.md', 'wire-contract.json',
        'v18-5-paid-service-trial-contract-v1.json', 'manifest.json'}
    assert bundle['definition']['guides'] == {'worker': 'SKILL.md', 'requester': 'requester-guide.md'}
    assert bundle['manifest']['descriptor']['specification_commit'] == '0f15a177b52221e21fa40f851d648afc929d6e3d'


def test_paid_trial_documentation_uses_skill_destination():
    prefix = 'https://kari.mayim-mayim.com/agent-task-specs/paid_service_trial.v1/1.0.0/'
    for name in ('README.md', 'docs/release_notes/v1.18.5.md'):
        text = (ROOT / name).read_text()
        assert prefix + 'SKILL.md' in text
        assert prefix + 'worker-guide.md' not in text
        assert prefix + 'requester-guide.md' in text


def test_missing_contract_bundle_fails_before_use(monkeypatch,tmp_path):
    monkeypatch.setattr(c,'__file__',str(tmp_path/'paid_service_trial_contract.py'))
    with pytest.raises(ValueError,match='unavailable or invalid'):c.load_contract_bundle()
