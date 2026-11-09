# Feedback task starting environment

Upstream: https://github.com/ecordell/pymacaroons
Upstream commit: `78c55c1d33a0b23ddc71140a9c999f957d79e9dd`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/functional_tests -o 'python_files=*_tests.py test_*.py'
```

Observed baseline (2026-11-09): `34 passed in 0.54s`
Whole-command wall time: 0.793 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
