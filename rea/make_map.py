#!/usr/bin/env python3
"""Generate a machine-readable capability map of REA's tool surface.

Input : /tmp/rea_tools.json (live tools/list dump)
Output: rea/agentic-re-map.json + rea/agentic-re-map.md

Fails loudly if any tool is unassigned, so the map can never silently drift
from the live surface.
"""
import json
import pathlib
import re
import sys
from collections import OrderedDict

_HERE = pathlib.Path(__file__).resolve().parent
SRC = str(_HERE / "tools.json")
OUT_JSON = str(_HERE / "agentic-re-map.json")
OUT_MD = str(_HERE / "agentic-re-map.md")

FAMILIES = [
    ("session", r"^open_binary$|^close_binary$|^binary_|^list_documents$|^current_document$|^set_current_document$",
     "Open, identify and close an analysis document.",
     "First call of any workflow: open the artifact, read overview, close when done.",
     "Document lifecycle is explicit; evidence bundles reference the opened document."),
    ("evidence", r"unknown|evidence_bundle|^build_reconstruction_obligation_ledger$|^evaluate_reconstruction_coverage$|^verify_reconstruction$",
     "Record, resolve and export what is known, unknown and proven.",
     "Wrap any conclusion you intend to rely on: record gaps, then export the bundle.",
     "Every claim carries confidence + authority + the artifact hash."),
    ("decompile", r"^procedure_|^batch_decompile$|^get_call_graph$|^build_call_path$|^resolve_native_call_targets$|^resolve_containing_procedure$|^analyze_function$",
     "Per-function decompilation, assembly, callers/callees and call paths.",
     "Core analysis loop: list procedures, then read pseudo-code and follow calls.",
     "Results are attached to a specific document + procedure address."),
    ("inventory", r"^list_|^search_|^find_xrefs_to_name$|^xrefs$|^address_name$|^address_to_file_offset$",
     "Enumerate what exists: procedures, names, strings, segments, bookmarks.",
     "Orientation: do this before reading code so you know the size of the surface.",
     "Counts and names come from the loaded document, never from heuristics."),
    ("navigate", r"^goto_address$|^next_address$|^prev_address$|^current_address$|^current_procedure$|^get_navigation_context$|^read_bytes$|^read_function_instructions$|^inspect_address_context$",
     "Move the cursor and read raw bytes or instructions at an address.",
     "Zoom in after inventory finds something interesting.",
     "Reads are bounded to the address range requested."),
    ("annotate", r"^set_|^comment$|^inline_comment$|^annotate_native_function$|^unset_bookmark$",
     "Write names, comments and bookmarks back into the document.",
     "Only after a conclusion is evidence-backed; annotations are analysis output.",
     "Writes are explicit function calls, never implicit side effects."),
    ("native_apple", r"^inspect_(native|macho|signature|plist|keyed_archive|asset_catalog)|^demangle_swift$|^analyze_swift_types$|^decode_interface_builder$|^get_objc_",
     "Mach-O / Swift / Objective-C structure inspection.",
     "Apple binaries: start here, not with generic disassembly.",
     "Structure comes from real load commands and type metadata."),
    ("managed_android", r"^inspect_managed|^compare_managed|^project_managed|^import_managed|^verify_managed|^trace_android|^search_android|^inspect_android",
     "Java/Kotlin and .NET managed code, plus managed-to-native boundaries.",
     "Android or .NET targets, and any app that mixes managed code with JNI/P-Invoke.",
     "Boundary verification is a first-class check, not an assumption."),
    ("web_js", r"^analyze_web_bundle$|^analyze_javascript_application$|^compare_javascript_export_shapes$|^compare_source_to_bundle$|^reconcile_javascript_runtime$|^trace_javascript_semantics$|web|electron|browser|javascript|^discover_webmcp_tools$",
     "JavaScript bundles, Electron apps, browser sessions and runtime reconciliation.",
     "When the target is JS/TS, Electron or a web app rather than a native binary.",
     "Static bundle view and runtime view are reconciled explicitly."),
    ("capture", r"^capture_|^correlate_static_and_runtime$|^compare_process_captures$|^observe_native_ui$|^trace_native_ui_action$",
     "Bounded process / UI / browser captures tied back to the static image.",
     "When behaviour must be observed, not inferred - keep the capture bounded.",
     "Capture scopes are bounded by the caller; static and runtime are correlated."),
    ("tracing", r"^trace_|^observe_",
     "Follow a feature, value or crash path across the application.",
     "After orientation, to answer \"how does X actually work / where does it break\".",
     "Traces walk real call references, not string matches."),
    ("diff", r"^compare_|^find_changed_behavior$",
     "Compare two versions, bundles, functions or captures.",
     "Patch-diffing and regression analysis across releases.",
     "Differences are structural, with both sides identified."),
    ("extract", r"^extract_|^inspect_firmware_regions$|^list_architectures$|^inspect_artifact$",
     "Unpack artifacts, firmware regions and architecture listing.",
     "Firmware, archives and multi-arch binaries.",
     "Extraction targets are reported explicitly."),
]


def main() -> int:
    doc = json.load(open(SRC))
    rules = [(fid, re.compile(rx), purpose, when, ev) for fid, rx, purpose, when, ev in FAMILIES]
    fam: "OrderedDict[str, dict]" = OrderedDict(
        (fid, {"id": fid, "purpose": p, "when_to_use": w, "evidence": e, "tools": []})
        for fid, _, p, w, e in FAMILIES)
    unassigned = []
    for t in doc["tools"]:
        for fid, rx, *_ in rules:
            if rx.search(t["name"]):
                fam[fid]["tools"].append({
                    "name": t["name"],
                    "required_inputs": t["required"],
                    "summary": t["description"].splitlines()[0][:160],
                })
                break
        else:
            unassigned.append(t["name"])

    if unassigned:
        print("UNASSIGNED:", unassigned, file=sys.stderr)
        return 1

    total = sum(len(f["tools"]) for f in fam.values())
    out = {
        "schema": "rekit/agentic-re-map/1",
        "generated_from": {
            "server": doc["server"], "version": doc["version"],
            "tool_count": doc["tool_count"], "prompt_count": doc["prompt_count"],
        },
        "note": ("Machine-readable capability map of the REA tool surface, derived from a live "
                 "tools/list call. Use it to pick the right tool family for a task instead of "
                 "guessing names. Regenerate with rea/dump_tools.py."),
        "invariants": [
            "Every tool operates on an explicitly opened document (see the session family).",
            "Conclusions should be recorded via the evidence family; bundles are sha256-pinned.",
            "Nothing in this surface executes a sample; captures are bounded and caller-scoped.",
            "A missing capability is reported, never invented.",
        ],
        "golden_chain": [
            {"step": 1, "tool": "open_binary", "why": "identify the artifact, get arch + sha256"},
            {"step": 2, "tool": "binary_overview", "why": "high-level shape before detail"},
            {"step": 3, "tool": "list_procedures", "why": "size the surface; pick real functions"},
            {"step": 4, "tool": "procedure_pseudo_code", "why": "read the function of interest"},
            {"step": 5, "tool": "get_evidence_bundle", "why": "capture the provenance of a claim"},
            {"step": 6, "tool": "close_binary", "why": "release the document"},
        ],
        "prompts": doc["prompts"],
        "families": list(fam.values()),
        "total_tools_assigned": total,
    }
    json.dump(out, open(OUT_JSON, "w"), indent=2)

    lines = [
        "# Agentic RE capability map",
        "",
        f"Machine-readable map of the **{doc['tool_count']}-tool** REA surface "
        f"(`{doc['server']}` v{doc['version']}), generated from a live `tools/list` call. "
        "The JSON next to this file (`agentic-re-map.json`) carries the same data with "
        "per-tool required inputs; use it when routing a task to a tool family.",
        "",
        "## Golden chain",
        "",
    ]
    for s in out["golden_chain"]:
        lines.append(f"{s['step']}. `{s['tool']}` — {s['why']}")
    lines += ["", "## Families", "", "| Family | Tools | Use when |", "| --- | --- | --- |"]
    for f in out["families"]:
        lines.append(f"| `{f['id']}` | {len(f['tools'])} | {f['when_to_use']} |")
    lines += ["", "## Invariants", ""]
    lines += [f"* {i}" for i in out["invariants"]]
    lines += ["", "## Shipped prompts", ""]
    lines += [f"* `{p}`" for p in doc["prompts"]]
    lines += ["", f"All {total} tools are assigned to exactly one family - the generator "
                  "refuses to emit a map that does not cover the live surface."]
    open(OUT_MD, "w").write("\n".join(lines) + "\n")
    print(f"OK: {total} tools in {len(out['families'])} families; prompts={doc['prompt_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
