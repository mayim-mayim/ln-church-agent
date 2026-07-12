#!/usr/bin/env python3
"""Compare the v1.16.1 and candidate public payment-boundary surfaces.

Both source trees are imported in isolated child processes so this audit cannot
accidentally compare two references to the same already-imported module.
"""

import argparse
import difflib
import json
from pathlib import Path
import subprocess
import sys


SNAPSHOT_CODE = r'''
import inspect
import json
import sys
import dataclasses

sys.path.insert(0, sys.argv[1])

from ln_church_agent.client import Payment402Client
from ln_church_agent.crypto.protocols import EVMSigner, LightningProvider
from ln_church_agent.models import ExecutionContext, PaymentPolicy
import ln_church_agent.exceptions as exceptions


def field_snapshot(model):
    result = {}
    if hasattr(model, "model_fields"):
        for name, field in model.model_fields.items():
            factory = field.default_factory
            factory_name = None if factory is None else "%s.%s" % (
                getattr(factory, "__module__", ""),
                getattr(factory, "__qualname__", repr(factory)),
            )
            result[name] = {
                "annotation": str(field.annotation),
                "default": repr(field.default),
                "default_factory": factory_name,
                "required": field.is_required(),
            }
        return result

    for field in dataclasses.fields(model):
        factory = field.default_factory
        has_factory = factory is not dataclasses.MISSING
        factory_name = None if not has_factory else "%s.%s" % (
            getattr(factory, "__module__", ""),
            getattr(factory, "__qualname__", repr(factory)),
        )
        result[field.name] = {
            "annotation": str(field.type),
            "default": (
                "MISSING" if field.default is dataclasses.MISSING
                else repr(field.default)
            ),
            "default_factory": factory_name,
            "required": field.default is dataclasses.MISSING and not has_factory,
        }
    return result


def protocol_members(protocol):
    names = set(getattr(protocol, "__annotations__", {}))
    for name, value in vars(protocol).items():
        if not name.startswith("_") and (
            callable(value) or isinstance(value, property)
        ):
            names.add(name)
    return sorted(names)


public_exceptions = {}
for name, value in vars(exceptions).items():
    if (
        inspect.isclass(value)
        and value.__module__ == exceptions.__name__
        and issubclass(value, Exception)
    ):
        public_exceptions[name] = [base.__name__ for base in value.__bases__]

snapshot = {
    "signatures": {
        "Payment402Client.__init__": str(inspect.signature(Payment402Client.__init__)),
        "Payment402Client.execute_detailed": str(inspect.signature(Payment402Client.execute_detailed)),
        "Payment402Client.execute_detailed_async": str(inspect.signature(Payment402Client.execute_detailed_async)),
    },
    "models": {
        "ExecutionContext": field_snapshot(ExecutionContext),
        "PaymentPolicy": field_snapshot(PaymentPolicy),
    },
    "protocols": {
        "EVMSigner": protocol_members(EVMSigner),
        "LightningProvider": protocol_members(LightningProvider),
    },
    "exception_direct_bases": public_exceptions,
}
print(json.dumps(snapshot, sort_keys=True, indent=2))
'''


def snapshot(source_tree):
    source_tree = Path(source_tree).resolve()
    completed = subprocess.run(
        [sys.executable, "-I", "-c", SNAPSHOT_CODE, str(source_tree)],
        cwd=str(source_tree),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "snapshot import failed for %s:\n%s"
            % (source_tree, completed.stderr)
        )
    return json.loads(completed.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()

    baseline = snapshot(args.baseline)
    candidate = snapshot(args.candidate)
    if baseline != candidate:
        before = json.dumps(baseline, sort_keys=True, indent=2).splitlines()
        after = json.dumps(candidate, sort_keys=True, indent=2).splitlines()
        print("\n".join(difflib.unified_diff(
            before, after, fromfile="v1.16.1", tofile="candidate", lineterm=""
        )))
        return 1
    print("public API compatibility snapshot: identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
