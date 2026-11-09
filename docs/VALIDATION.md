# Candidate validation and promotion

This implements the PR1–PR4 code scope from `PLAN.md` on top of `5dbd1f9`.
PR5a/PR5b are deferred until the security patch is deployed. A passing local
candidate does not authorize restarting or replacing an existing deployment.
The observed local service uses Python 3.10; its environment and state are not
modified by this work.

## Environments

Use a new Python 3.11 or 3.12 virtual environment. `requirements.txt` includes
`constraints.txt`; `requirements-ens.txt` includes the base requirements and
Web3. Both profiles use normal pip dependency resolution. The shared constraint
set pins the resolved base and optional ENS packages; constraints alone do not
install optional packages. Linux 3.11/3.12 are the verification matrix; later
Python/platform combinations require their own installation and test results.

PyMISP stays on the 2.4 series at 2.4.198. This removes the old jsonschema<4
constraint without requiring a PyMISP 2.5 migration. Web3 7.16.0 is tested through
real loopback JSON-RPC, including the installed provider's deadline/retry path.
Web3 6.20.4 was not selected: its lru-dict build needed Python development
headers missing from the clean local Python 3.12 installation. The new direct
jsonschema requirement preserves existing API schema tests after PyMISP stopped
pulling it transitively.

## Local commands

Install dependencies and Chromium with network available, then run test bodies
inside a loopback-only namespace. Use an explicitly selected candidate Python;
do not implicitly reuse a running service's `.venv`.

```bash
python3.12 -m venv /path/to/new-candidate
/path/to/new-candidate/bin/python -m pip install -r requirements-bootstrap.txt
/path/to/new-candidate/bin/python -m pip install -r requirements-ens.txt
python3.12 -m venv /path/to/new-tools
/path/to/new-tools/bin/python -m pip install -r requirements-bootstrap.txt
/path/to/new-tools/bin/python -m pip install -r requirements-ci.txt
npm ci
npx playwright install --with-deps chromium
export PYTHON=/path/to/new-candidate/bin/python
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
bash scripts/ci/loopback_only.sh make test
bash scripts/ci/loopback_only.sh make security-regression
bash scripts/ci/loopback_only.sh make botnet-coverage
bash scripts/ci/loopback_only.sh make lint RUFF=/path/to/new-tools/bin/ruff
bash scripts/ci/loopback_only.sh npm run test:e2e
bash scripts/ci/audit_environment.sh "$PYTHON" /path/to/new-tools/bin/pip-audit /path/to/new-audit-output
```

The network wrapper refuses host-network fallback. It needs Linux network
namespaces, `ip`, and `setpriv`; on hosts disallowing user namespaces it tries
passwordless `sudo unshare` and drops all capabilities before running tests.
The audit runs separately with network access. Its output directory must not
already exist. Scanner errors, skipped packages, incomplete/empty JSON, and
known vulnerabilities fail the gate. No advisory suppressions are configured.
Inventories use `pip freeze --all`, including setuptools (required by GeoIP)
and pip, even on Python 3.11 where default freeze hides them. The bootstrap
requirements pin the installer in new candidate/tool environments; original
service environments remain unchanged. Installer vulnerabilities block the
same audit rather than being omitted as tooling debt.

The fixed security corpus is an offline regression set, not an estimate of
coverage on unseen threats. Original observations in `docs/ens/` and the tests
remain unchanged; the deployment example deliberately contains no targets.
CLI tests verify no RPC occurs when neither an ENS name nor an explicit node
is provided, and verify name, node, combined target and direct resolver calls.

## Test instrumentation

Fault-injection helpers preserve the caller's tracing/profiling hooks. Python
3.11 uses guarded legacy opcode tracing. On Python 3.12, actual instruction
faults use code-local `sys.monitoring` events with a thread-owner filter: legacy
opcode flags otherwise leave interpreter-wide instrumentation overhead after
restoration. Tool IDs and callbacks are released on normal and exceptional
exits; exhausted IDs or an existing instruction owner cause explicit refusal,
not replacement of another observer. Independent line observers remain active.
The deliberately intrusive legacy-hook and frame-flag controls run in fresh
subprocesses; actual lifecycle faults remain in the native collector's process.
Fresh-process and native-coverage tests retain exact allocation boundaries,
once-only faults, alias retirement, budget restoration and subsequent work.
Ordered regressions execute real faults, the unchanged 1,101-entry workload
and a measured sentinel. No time budget, coverage core or floor is relaxed.

## Remote and operational gates still required

- Run the pushed candidate on independent GitHub runners. Local workflow
  validation is not a hosted Actions pass.
- Demonstrate a deliberately broken assertion fails a disposable PR, then
  configure branch protection using the actual unit, lint, browser and
  dependency-audit check names. The workflow file alone does not configure
  branch protection or activate a schedule until published.
- Confirm the production Python minor and whether ENS/MISP run together;
  approve the Python 3.10 migration schedule before promotion.
- Back up configuration, history/delivery SQLite and the security database
  consistently. Verify restore and state replay on isolated copies, with only
  mock destinations. Preserve the prior commit/environment and resolved pins.
- Ensure only one instance owns state writes and external delivery. After an
  approved switch, compare DNS errors/timeouts, notification failures/duplicates,
  reappearance and removal behavior for 24 hours. Authentication failure promoted
  to managed state, sequence rollback, duplicate delivery or early removal is a
  stop condition. Reconcile already-delivered events before restoring backups.

No commit, push, branch protection update, live service restart, production
backup/restore, external notification, or 24-hour observation is performed by
adding these candidate files.
