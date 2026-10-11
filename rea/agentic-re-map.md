# Agentic RE capability map

Machine-readable map of the **125-tool** REA surface (`rea` v4.1.0), generated from a live `tools/list` call. The JSON next to this file (`agentic-re-map.json`) carries the same data with per-tool required inputs; use it when routing a task to a tool family.

## Golden chain

1. `open_binary` — identify the artifact, get arch + sha256
2. `binary_overview` — high-level shape before detail
3. `list_procedures` — size the surface; pick real functions
4. `procedure_pseudo_code` — read the function of interest
5. `get_evidence_bundle` — capture the provenance of a claim
6. `close_binary` — release the document

## Families

| Family | Tools | Use when |
| --- | --- | --- |
| `session` | 7 | First call of any workflow: open the artifact, read overview, close when done. |
| `evidence` | 10 | Wrap any conclusion you intend to rely on: record gaps, then export the bundle. |
| `decompile` | 13 | Core analysis loop: list procedures, then read pseudo-code and follow calls. |
| `inventory` | 16 | Orientation: do this before reading code so you know the size of the surface. |
| `navigate` | 9 | Zoom in after inventory finds something interesting. |
| `annotate` | 9 | Only after a conclusion is evidence-backed; annotations are analysis output. |
| `native_apple` | 15 | Apple binaries: start here, not with generic disassembly. |
| `managed_android` | 11 | Android or .NET targets, and any app that mixes managed code with JNI/P-Invoke. |
| `web_js` | 16 | When the target is JS/TS, Electron or a web app rather than a native binary. |
| `capture` | 6 | When behaviour must be observed, not inferred - keep the capture bounded. |
| `tracing` | 4 | After orientation, to answer "how does X actually work / where does it break". |
| `diff` | 5 | Patch-diffing and regression analysis across releases. |
| `extract` | 4 | Firmware, archives and multi-arch binaries. |

## Invariants

* Every tool operates on an explicitly opened document (see the session family).
* Conclusions should be recorded via the evidence family; bundles are sha256-pinned.
* Nothing in this surface executes a sample; captures are bounded and caller-scoped.
* A missing capability is reported, never invented.

## Shipped prompts

* `investigate_feature`
* `compare_application_versions`
* `verify_reconstruction`
* `trace_crash`
* `audit_residual_unknowns`
* `prepare_bounded_process_capture`

All 125 tools are assigned to exactly one family - the generator refuses to emit a map that does not cover the live surface.
