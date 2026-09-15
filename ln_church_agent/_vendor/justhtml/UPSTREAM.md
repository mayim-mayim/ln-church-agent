# JustHTML vendor provenance

This isolated copy supplies the HTML5 document parser for
`immediate_visit_utf8.v1`. It was extracted directly from the upstream wheel,
then given the compatibility edits recorded in `compatibility.patch`. The
earlier architecture research prototype was not copied into this package.

| Input | Identity |
| --- | --- |
| Project | [EmilStenstrom/justhtml](https://github.com/emilstenstrom/justhtml) |
| Upstream version | `3.11.2` |
| Wheel | `justhtml-3.11.2-py3-none-any.whl` |
| Wheel SHA-256 | `366986de83fab5f7ab643f79ffb3ad44dbaeb63f34b6361b955930575417cdd2` |
| License | MIT; `LICENSE` is byte-for-byte upstream `justhtml-3.11.2.dist-info/licenses/LICENSE` |
| License SHA-256 | `fc806f290894e4f219467135fb21f33048f8d5a817f0f8284246d72da29d572e` |
| Import namespace | `ln_church_agent._vendor.justhtml` |

The upstream wheel requires Python 3.10 or later. The SDK keeps its existing
Python 3.8.1 minimum. All upstream `justhtml/` package files, including
`py.typed`, are retained. The wheel's distribution metadata and console-script
registration are not installed. No third-party import named `justhtml` is
created or resolved, and no dependency is downloaded during task execution.

## Compatibility edits

`compatibility.patch` is a unified diff against the wheel's `justhtml/`
directory. It changes 24 upstream source files and adds `_compat.py`:

- Absolute package imports use the isolated SDK namespace. Existing relative
  imports and relative `import_module` calls remain relative to that namespace.
- Runtime type aliases use `typing.Union`, `typing.Tuple`, and related typing
  forms available in Python 3.8. Three generic class bases use `typing.List` or
  `typing.Dict`. `TypeAlias` has a local annotation-marker fallback where the
  standard library does not provide it. `core/errors.py` postpones annotations.
- The local dataclass adapter forwards upstream options unchanged on Python
  3.10 and later. On Python 3.8 and 3.9 it omits only the unavailable `slots`
  option; these internal record objects therefore have an instance dictionary.
- Exact `str.removeprefix` and `str.removesuffix` operations use equivalent
  local helpers. The single strict-zip call uses a local iterator that preserves
  the equal-length requirement and raises `ValueError` on unequal lengths.

These changes do not alter tokenization tables, HTML tree-building rules,
namespace handling, error recovery, parser options, or sanitizer policy rules.
The SDK profile uses document mode, `sanitize=False`,
`scripting_enabled=False`, and
`_parser_opts=ParserOptions(discard_bom=False)`. Its caller performs strict UTF-8
decoding and removes at most one leading BOM before parsing.

## Focused implementation evidence

The vendored runtime was checked on CPython 3.12.14 and CPython 3.8.20 on Linux.
On each interpreter, all 12 fixed public HTML vectors (`H01` through `H12`)
matched their specified structure or empty-structure result, and all applicable
JCS preimages and SHA-256 expectations matched. All 40 non-CLI runtime modules,
including the compatibility helper, imported in the isolated namespace; no
top-level `justhtml` module was loaded. Prefix, suffix, and equal/unequal strict
zip cases were also checked.

These are dependency-level implementation checks. They do not assert a full
SDK installation, full upstream HTML5 corpus parity, Windows execution, or an
exact Python 3.8.1 patch-level execution. The SDK's existing minimum-version
contract remains unchanged. Candidate acceptance and release are separate
decisions.
