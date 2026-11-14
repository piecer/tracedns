# Console views and evidence ownership

The console starts with recorded results, not an operations report. Navigation is
grouped into Monitoring, Lookup & verify, Analysis and Operations. Account,
password, session and audit links are in **Account**. Server RBAC remains the
permission boundary; hiding a control is not authorization.

## Basic, selected and advanced views

| View | Basic view | Explicit detail or advanced action |
|---|---|---|
| Status | Target, type, recorded observation, managed IP summary, last observation and page range | **Details** selects one target. Raw values, decoder/server evidence and History are separate disclosures/actions. |
| All IPs / Valid IPs | IP, related targets, last observation and enrichment/validity | One selected detail exposes retained occurrence counts and AS/VT provenance. VT work limits are separate. |
| Query | Input type and independent current/history/MISP statuses | Cached matches page in groups of 50. Opening raw evidence makes no new request. **Search** is an explicit read; operator/admin searches also query MISP under the existing policy. |
| Domain Verify | Type-specific required input, lookup result and registration eligibility | Advanced JSON/budget/worker settings; paged decoder/server/IP evidence; full received response. **Apply decoder and validate** changes inputs and sends a new validation request. |
| Domain Analysis | Compact domain/lifecycle table with explicit current-page IP coverage | **View** selects one cached domain. IP/AS/country evidence and page summaries mount on expansion. **Manage domains** enables non-resolving-target removal, with confirmation. |
| Botnet IP Analysis | Existing input/profile/job flow, quality and coverage, Table/Graph/Map | One pair/cluster inspector, job metadata and paged per-IP evidence. Inspection is distinct from reanalysis. |
| Settings | Complete target identities, registration/configuration-change dates, search and save status | Existing target editors; advanced server options; separate integration secret editor and decoder settings. |
| Delivery | Compact backend/worker state and visible loss/uncertainty | **Delivery details** and **Delivery diagnostics · manual read**. Opening diagnostics does not perform its read. |

Query's IPv4 path uses the local `/ip` index. Other input, including IPv6, is a
text fragment matched against current values and the histories of currently
listed targets. This is not a global history search or an IPv6-specific IP index.
Current, history and MISP failures are independent; partial history coverage is
not reported as a complete empty result. A Query link is an explicit search
entry point, not merely cached inspection.

Registration eligibility is not lookup success. A valid DHT target or RPC
profile can be registrable even when its current lookup fails. DHT last-confirmed
signed evidence remains separate from the latest attempt and bounded coverage.
RPC authenticated C2 entries remain separate from relay, download and mining
roles. Full keys, endpoints, role evidence and decimal-string sequences remain
available; a decoded address is not proof of infection or reachability.

## Counts and clocks

- Unread metrics start as `—`, not zero. Failure, no matches, first read, partial
  coverage and stale previous data have different meanings.
- **Targets in Status snapshot (total)** comes from that accepted snapshot.
  **Managed IPs · current Status page** is not a global IP total or configured
  target count. **Status read (browser)** is not an observation timestamp.
- All-IP and Valid-IP counts belong to their last accepted reads. Valid means
  syntactically valid, not safe. The recent-time filter belongs to Valid IPs.
- Retained occurrence counts are not independent DNS queries, infections or
  incidents. Domain Analysis evidence and AS/country summaries are page-scoped;
  lifecycle status is domain-wide. A domain can span server pages.
- Global substring search and the cached current-page domain selector are
  different operations. Prepared pages follow server-provided offsets, including
  byte-short pages. They do not automatically collect the whole dataset.
- Legacy IP downloads retain their first-5,000-row limit and do not inherit the
  Valid-IP recent-time/validity filter. Raw download links are explicit, not an
  automatic fallback from a failed prepared read.

## Failures, generations and privacy

Registered local owners display their own ordinary failures. Their identity is
owner + query + fixed error code; request generation is a separate fence.
Repeated failures update that identity rather than append alerts. Only a valid,
accepted success for the same owner/query clears its transient failure. A newer
unrelated success, elapsed time or collapsing a panel is not recovery.

Authentication, CSRF/permission and audit failures retain global security
ownership. Unconverted requests and a missing feedback asset retain visible
global fallback. The additive `X-TraceDNS-Security-Error: security_unavailable`
header identifies security-boundary 503 responses before headers are sent; it
does not change ordinary service/prepared 503 responses. A failure after headers
have already been sent cannot replace that response, and the header does not
claim to repair that pre-existing limitation.

The marker also covers uncaught exceptions escaping dispatch into that outer
boundary. It identifies the catching boundary, not independent proof that the
audit store itself failed.

Permission/session invalidation retires protected selections, drafts and
analysis exports. Cached role information alone cannot reopen management after
invalidation; reload to establish current access. Abandoned reads and delayed
responses cannot publish over successor owners, including A→B→A and responses
from adapters that ignore abort. Error bodies and JSON-parser/provider exception
text are not used as lookup/analysis failure copy.

Saved configurations and API projections retain their existing redaction rules.
Authorized raw evidence is not the same format as the closed delivery diagnostic
export; do not assume every general-purpose raw export has the diagnostic
schema's stronger privacy restrictions.

## Drafts and explicit mutations

Settings Load/Save, target removal and Verify Add do not overwrite edits made
while their responses were pending. A retained draft keeps its own revision;
background reads and unrelated writes do not silently rebase it. A conflict or
uncertain POST remains visible; writes are not automatically replayed.

An already-submitted Verify Add is separate from cancelling its validation.
Until its outcome is known, another Add is blocked. **Review saved targets** is
an explicit read-only reconciliation step; acknowledge the review before retrying.
This does not load or rebase the independent Settings draft. A non-sensitive
per-tab session-storage marker preserves uncertainty across reload when browser
storage is available; private target evidence is not stored in that marker.

Blank secret inputs preserve saved values. Only an explicit **Clear saved value**
removes one. Integration save receipts describe the committed redacted settings
and revision; runtime-apply warnings remain warnings. Configuration presence is
not proof of connectivity or delivery readiness. Failed/unapplied reloads do not
qualify a real Teams test merely because the old draft revision is retained.

**Force Resolve** uses the current form to select configured target identities,
then uses saved definitions/providers. It does not save unsaved definitions.
Acceptance means admission, not completed resolution. **Send real Teams test**
and target-scoped resend remain separate explicit actions with their existing
warnings and permissions. Domain Analysis removal requires Manage mode and
confirmation; leaving the view closes management and clears its selection.

## Analysis interaction and cancellation

- **Inspect pair/cluster** reads the accepted cached result without changing the
  input list or making a provider request. Closing restores focus to its control.
- **Analyze cluster** replaces the input with the cluster's IPs and runs Per-IP
  enrichment. A Map country bubble replaces input with that country's IPs and
  reruns relationship analysis. These are not passive selections.
- Graph node/edge selection shows cached evidence. Table controls provide a
  keyboard alternative; Map country bubbles support keyboard activation.
- Coverage/quality and display-limit explanations stay visible outside job
  metadata. Relationship strength, botnet evidence and confidence remain
  different values; a connected cluster is not a same-botnet verdict.
- Explicit Cancel stops browser polling and requests server cancellation.
  Pending, confirmed and unconfirmed server cancellation are distinguished.
  Running work may be uncancellable. Prior successful results/exports retain
  their original ownership and are labeled stale when a rerun fails.
- Leaving/hiding the analysis view stops browser publication and disposes visual
  detail; it does not silently send a cancellation POST or claim the server
  stopped. Already dispatched provider/server work may continue. Returning does
  not automatically submit another analysis.
- Foreground/persisted-page restoration rebuilds the selected accepted cached
  Table/Graph/Map view even when automatic refresh is paused. It preserves the
  result's coverage warnings and does not resume detached server-job polling.

## Rendering and request limits

These are presentation limits, not claims that every underlying legacy response
or retained Settings draft is globally bounded by the same DOM budget.

| Boundary | Limit / policy |
|---|---|
| Prepared primary page | Existing server cap, at most 200 primary rows; 202/unchanged/stale/422 behavior retained |
| Selected History | At most 50 events mounted per client page; every returned event remains reachable |
| Query source results | 50 cached entries per source page |
| Verify evidence | One active evidence disclosure, eight entries per page |
| Domain Analysis detail | 12 IP evidence rows; eight rows per summary table |
| Per-IP enrichment detail | Eight entries per category per cached page; full received JSON on explicit expansion |
| Relationship tables | Existing 1,000 pair / 1,000 cluster display caps |
| Relationship Graph | Existing 400 node / 600 edge display caps |
| Common delivery state | At most 40 mounted descendants in the initial health region in the fixed fixtures |
| Selected detail / diagnostics | At most 500 additional elements in the corresponding acceptance fixtures |
| Delivery health | 4,096-byte response bound, 10-second read lifetime, minimum 15-second request spacing |
| Manual diagnostics | 32,768-byte bound, 10-second read lifetime; no automatic read/poll |

Collapsed large evidence is not prebuilt as hidden rows. Replacement/collapse
removes owned detail, and late Map assets cannot mount a hidden predecessor.
Cached tables paginate without new provider calls. History still receives the
legacy whole-response body: client pagination does not add server pagination or
solve that transport limit.

## Navigation, deep links and verification scope

Native disclosures, focusable result headings, a main landmark, a skip link and
current navigation state remain available. `#settings-alerts`, `#deliveryHealth`
and `#deliveryDiagnostics` open the appropriate view/disclosure and focus its
heading/control. Tokens, secrets and raw records are not added to deep links.

The `tests/e2e/view-*.spec.js` fixtures exercise authenticated real HTTP/frontend
paths, prepared producers, failures, ownership races, DOM/request limits, actual
Graph/Map pixels and all three roles. Whole-view captures cover 1366×768,
390×844 and a 200%-equivalent CSS-layout/physical-pixel configuration. Accessibility
checks include keyboard interactions and Chromium's accessibility tree, not a
physical screen reader or browser-chrome zoom-key test.

The README image is an uncropped 1366×768 viewport of the actual shipped frontend
with reserved synthetic `.test` / `192.0.2.0/24` records and genuine disabled
integration health. No monitoring/provider worker or production configuration is
used for that capture. Isolated tests, full canonical gates, hosted CI and the
user's deployed page are separate evidence. Deployment/restart and live-provider
validation require separate authorization; local success does not establish
that a previously reported production symptom has been reproduced or resolved.
