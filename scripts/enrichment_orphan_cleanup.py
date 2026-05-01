# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""One-shot maintenance utility: re-point findings whose `enrichment_id`
points at an enrichment row whose signature no longer matches the finding.

Background
----------
Before 2.1.1 the enrichment cache key was a SHA-256 of just
  (source_tool | normalized_title | cwe | owasp_category)

That collapsed too many distinct findings onto the same row. A single
"wapiti anomaly: Internal Server Error" enrichment ended up shared across
dozens of distinct (parameter, endpoint) combinations — so the LLM-authored
remediation text for one finding mis-attached to many sibling findings, and
an admin's manual edit on one row silently rewrote them all.

2.1.1 widens the hash to include `module`, `parameter`, and a normalized
URL path. New findings are written under the new hash. Rows already attached
to existing findings keep their stale broad-hash linkage until something
fixes them — that's what this script does.

Behavior
--------
For every row in `findings` that has a non-NULL `enrichment_id`:
  1. Recompute the new signature for that finding.
  2. Look up the enrichment row currently linked.
  3. If the linked row's signature_hash already matches → leave it alone.
  4. If the linked row is locked (manual admin edit) → leave it alone, even
     if the hashes differ. The admin chose this guidance deliberately and
     we never silently strip a curated entry.
  5. Otherwise → NULL out the finding's `enrichment_id`. The next read by
     the API or report renderer will re-run `enrichment.get_or_create()`
     and either:
       a) hit a properly-keyed cached row (other findings of the same
          new-hash signature have already been re-enriched);
       b) hit the static catalog;
       c) hit the legacy fallback if an admin had locked a manual entry
          under the old hash;
       d) call the LLM (paid) and write a new row keyed under the new hash.

Run modes
---------
  --dry-run     report what would change, write nothing  (default)
  --commit      perform the updates
  --assessment N   limit to a single assessment (useful for staged rollout)

Run inside the nextgen-dast container so PYTHONPATH and DB credentials are
already configured:

  docker exec -it nextgen-dast python3 /app/scripts/enrichment_orphan_cleanup.py --dry-run
  docker exec -it nextgen-dast python3 /app/scripts/enrichment_orphan_cleanup.py --commit
"""
from __future__ import annotations

import argparse
import json
import sys

sys.path.insert(0, "/app")
import db                                       # noqa: E402
import enrichment as enrichment_mod             # noqa: E402


def _row_to_finding(row: dict) -> dict:
    """Reconstruct just enough of the parser-shape finding dict that
    `signature()` needs. The DB stores `raw_data` as a JSON string; pre-
    parse it so the helper that pulls `module` / `parameter` from raw_data
    sees the structured form."""
    raw = row.get("raw_data")
    parsed_raw: dict = {}
    if isinstance(raw, str) and raw:
        try:
            parsed_raw = json.loads(raw)
        except Exception:
            parsed_raw = {}
    elif isinstance(raw, dict):
        parsed_raw = raw
    return {
        "source_tool": row.get("source_tool") or "",
        "title": row.get("title") or "",
        "cwe": row.get("cwe") or "",
        "owasp_category": row.get("owasp_category") or "",
        "evidence_url": row.get("evidence_url") or "",
        "raw_data": parsed_raw,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--commit", action="store_true",
                    help="actually update rows; default is dry-run")
    ap.add_argument("--assessment", type=int, default=None,
                    help="restrict to one assessment_id")
    args = ap.parse_args()

    where = "WHERE f.enrichment_id IS NOT NULL"
    params: tuple = ()
    if args.assessment is not None:
        where += " AND f.assessment_id = %s"
        params = (args.assessment,)

    rows = db.query(
        f"""SELECT f.id, f.assessment_id, f.source_tool, f.title, f.cwe,
                   f.owasp_category, f.evidence_url, f.raw_data,
                   f.enrichment_id,
                   e.signature_hash AS linked_sig,
                   e.is_locked AS linked_locked,
                   e.source AS linked_source
              FROM findings f
              JOIN finding_enrichment e ON e.id = f.enrichment_id
              {where}""",
        params,
    )

    aligned = 0
    locked_kept = 0
    cleared = 0
    for row in rows:
        finding = _row_to_finding(row)
        new_sig = enrichment_mod.signature(finding)
        if row["linked_sig"] == new_sig:
            aligned += 1
            continue
        if row["linked_locked"]:
            locked_kept += 1
            continue
        cleared += 1
        if args.commit:
            db.execute(
                "UPDATE findings SET enrichment_id = NULL WHERE id = %s",
                (row["id"],))

    mode = "COMMIT" if args.commit else "DRY-RUN"
    print(f"[{mode}] scanned: {len(rows)} findings with enrichment_id set")
    print(f"  already-aligned (no-op): {aligned}")
    print(f"  locked manual rows kept: {locked_kept}")
    print(f"  cleared (set enrichment_id=NULL): {cleared}")
    if not args.commit and cleared:
        print("  → re-run with --commit to apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
