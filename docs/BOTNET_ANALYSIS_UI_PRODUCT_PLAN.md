# Botnet Analysis UI Product Hardening Plan

## 1. Objective

Upgrade the existing Botnet IP Analysis screen from a feature-complete diagnostic view to a product-ready analyst workflow without changing the relationship-analysis API contract or scoring semantics.

The target is a UI that:

- makes the primary workflow obvious;
- communicates input size, running, cancellation, success, incomplete, and error states;
- keeps expert tuning available without overwhelming the default path;
- makes large results easier to understand and export;
- remains usable with keyboard, screen reader, narrow viewport, and reduced motion;
- has executable regression tests for every new state transition and interaction.

## 2. Baseline and Audit Evidence

Baseline on `hardening/botnet-analysis-ui-product`:

- `make test`: 241 Python tests passed and 26 Node subtests passed;
- `make lint`: passed;
- `make botnet-coverage`: 93% branch coverage for `http_api/relationship_handlers.py`;
- desktop browser inspection: the Botnet section occupies roughly 1,250 px vertically before any results and exposes all expert controls at once.

### Product UX findings

1. Three similarly weighted actions (`Load from MISP`, `Analyze IP List`, and `Relationships`) make the primary path ambiguous.
2. Input scale is not visible until after submission; analysts cannot see token or duplicate counts while preparing data.
3. Relationship tuning, profiles, view switching, result tables, and unrelated per-IP analysis are presented at the same visual level.
4. Running and terminal states are mainly represented by table text. Cancellation exists at the API lifecycle level but is not a first-class user action.
5. Empty tables consume substantial space and resemble incomplete rendering rather than intentional empty states.
6. Quality/completeness metadata is verbose but not summarized into analyst-facing health signals.
7. Results cannot be exported directly for evidence handoff.

### Accessibility and responsive findings

1. Table/Graph/Map controls visually behave as tabs but lack complete `tablist` / `tab` / `tabpanel` semantics and selected-state updates.
2. Interactive cluster rows and map markers are mouse-oriented and need keyboard activation and accessible names.
3. Busy, cancelled, complete, and failed states need a stable live region and explicit status text.
4. Focus visibility and reduced-motion behavior are not defined consistently.
5. Dense inline controls and wide tables overflow narrow viewports; table scrolling is not consistently contained or labelled.
6. Status and risk must not rely on color alone.

### Test-quality findings

1. Existing Node-backed tests already execute submit/poll/cancel lifecycle code and are the correct place to extend behavioral coverage.
2. New pure helper functions should be tested by extracting and executing their real JavaScript bodies rather than matching source strings only.
3. HTML/CSS accessibility contracts should verify IDs, labels, live-region semantics, tab relationships, and responsive containers.
4. Browser smoke QA must verify desktop and narrow-layout behavior, keyboard activation, no console errors, and terminal states.
5. Backend coverage remains a release gate even though this phase intentionally avoids backend semantic changes.

## 3. Scope and Priorities

### P0 — Workflow and state clarity

- Recompose the Botnet section into input, actions, relationship workbench, and secondary per-IP results.
- Add live input token/unique/duplicate counts and a clear empty-input message.
- Give `Relationships` primary emphasis; keep MISP import and per-IP enrichment secondary.
- Add an explicit Cancel button that aborts the active request and triggers best-effort server job cancellation.
- Add stable `idle`, `running`, `complete`, `cancelled`, and `error` status rendering.
- Keep terminal state visible and actionable after timeout, abort, or server error.

Acceptance criteria:

- one relationship run can be cancelled from the UI;
- cancelled work does not remain in a misleading loading state;
- stale requests cannot overwrite a newer run;
- status changes are announced in a polite live region;
- executable tests cover success, cancellation, and failure.

### P0 — Result comprehension and quality

- Add summary metrics for analyzed IPs, displayed relationships, clusters, and candidate/completeness coverage.
- Add a quality banner that distinguishes complete, incomplete/truncated, and VT partial/unavailable results using text plus iconography.
- Replace raw empty table shells with intentional empty-state copy until results exist.
- Preserve detailed metadata for expert inspection.

Acceptance criteria:

- metrics tolerate absent or older response fields;
- incomplete candidate evaluation and VT gaps are never presented as complete;
- zero-result success is visually distinct from failure;
- tests cover complete, incomplete, VT-partial, and empty results.

### P1 — Progressive disclosure and result operations

- Keep profile selection visible while moving low-level tuning under an Advanced settings disclosure.
- Add relationship result filtering over pair endpoints/evidence and cluster summary fields.
- Add a JSON export based only on the last successful result; disable export before data exists.
- Preserve existing pair visibility toggle and view switching.

Acceptance criteria:

- presets and custom persistence retain their current semantics;
- filtering is case-insensitive and does not mutate cached results;
- export omits no result fields and uses a deterministic filename shape;
- pure filter/export helpers have executable tests.

### P1 — Accessibility and responsive behavior

- Implement complete tab semantics and selected state for Table, Graph, and Map.
- Add keyboard activation to interactive cluster rows and SVG map markers.
- Add labelled horizontal scrolling containers around wide tables.
- Add focus-visible styles, minimum touch targets, narrow-viewport stacking, and reduced-motion handling.
- Ensure headings, labels, descriptions, and control relationships remain meaningful without visual context.

Acceptance criteria:

- keyboard users can run, cancel, switch views, inspect clusters, and activate map markers;
- active tabs expose `aria-selected=true` and inactive panels are hidden;
- no page-wide horizontal overflow at the mobile breakpoint;
- contract tests cover semantic relationships and keyboard handlers.

## 4. Implementation Workstreams

### Workstream A — Information architecture and responsive CSS

Files:

- `dns_frontend.html`
- `dns_frontend.css`
- `tests/test_relationship_frontend_product.py`

Deliverables:

- semantic workbench structure;
- input status and lifecycle live regions;
- metrics and quality containers;
- advanced disclosure, filter, export, cancel, tabs, and table-scroll markup;
- responsive, focus, status, empty-state, and reduced-motion styles.

### Workstream B — Interaction and rendering logic

Files:

- `dns_frontend.js`
- `tests/test_relationship_frontend_product.py`
- `tests/test_relationship_frontend_contract.py`

Deliverables:

- input summary helpers;
- explicit run-state controller;
- result summary/quality model and renderer;
- filtering and deterministic export serialization;
- accessible tab state and keyboard activation;
- cancellation terminal-state handling.

### Workstream C — Independent QA and regression review

Files inspected:

- all changed frontend files;
- relationship API handlers and response contracts;
- existing relationship tests and Makefile gates.

Deliverables:

- browser console and visual smoke results;
- narrow-layout overflow check;
- keyboard/a11y contract review;
- full test, lint, syntax, coverage, and diff checks;
- independent review of race conditions, stale state, and backwards compatibility.

## 5. TDD Sequence

1. Add failing structural contracts for the workbench, live regions, cancel/export controls, tab semantics, and scroll containers.
2. Add failing executable helper tests for input summaries, quality modeling, filtering, and export serialization.
3. Add failing lifecycle tests for explicit cancellation and terminal-state rendering.
4. Implement the minimum HTML/CSS/JavaScript for each red test group.
5. Run focused frontend tests after every slice.
6. Run full regression and coverage gates.
7. Perform browser smoke QA and add a regression test for every defect found.
8. Request independent sub-agent review and resolve high/medium findings before final verification.

## 6. Required Verification Gates

All must pass before completion:

```text
python -m pytest -q tests/test_relationship_frontend_contract.py tests/test_relationship_frontend_product.py
node --check dns_frontend.js
make test
make lint
make botnet-coverage
git diff --check
```

Browser QA:

- desktop workflow from input through successful render;
- explicit cancellation and recoverable rerun;
- error and incomplete-result visibility;
- keyboard tab switching and interactive result activation;
- narrow viewport without page-level horizontal overflow;
- no JavaScript console exceptions.

## 7. Non-goals

- Changing similarity scores, candidate generation, VT lookup rules, or backend limits.
- Introducing a frontend framework or build pipeline.
- Replacing existing graph/map libraries.
- Persisting sensitive input or analysis result data in browser storage.
- Adding server-side report storage in this phase.

## 8. Rollback and Compatibility

- Changes remain additive to the existing API response schema.
- Existing IDs used by backend-independent JavaScript are retained unless tests prove every reference is migrated.
- The last successful result stays in memory only and is cleared on page reload.
- If an optional response field is absent, metrics display a neutral fallback rather than throwing.
- Advanced settings preserve existing defaults and local custom-profile storage keys.
