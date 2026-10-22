# Reading and reproducing the decision ledger

The inventory contains exactly 11,731 commits reachable from the pinned ACK
boundary but not the pinned LTS tip. `candidates.tsv` is the readable table;
`candidates.jsonl` preserves structured evidence. **Check `review_status` as well
as `disposition`: `draft-net-reconciliation` rows are not completed review.**

A candidate is not necessarily a patch to apply. This history includes old
Android-mainline merges, intermediate implementations, removals, reapplies,
upstream equivalents, and ABI bookkeeping. Replaying all of it would both
resurrect removed features and reverse later LTS fixes. The implementation uses
final subsystem code, with explicit adaptations, instead.

For each non-merge, `files` is its parent diff. For each merge, `files` is its
**unique resolution delta**, reconstructed by Git's remerge diff. All 2,623
merges were reconstructed; 2,112 had no resolution delta, and 511 had a nonempty
one. The complete original resolution patches are in
`evidence/merge-resolutions.patch`. Nonempty merge rows include a patch digest,
hunk count and per-path decisions, separately from the merged parent commits.
`evidence/merge-hunk-examination.json` additionally indexes all 10,450 resolution
hunks, their digests and literal witnesses in ACK, LTS and the port. Literal
witnesses are not semantic equivalence proofs. The remerge preimage contains
conflict markers and must not be mistaken for either real parent. Rename-only
resolutions record both paths; the corrected index retains the original path
list for the dm-bow documentation rename as audit history.

`evidence/path-review.json` records the exact ACK, normalized ACK, common-ancestor,
LTS and port blob IDs for every candidate path, with the source decision and
implementation commits. The normalized ACK is an intermediate analysis tree:
explicit later LTS restorations override it. It removes historical KABI wrappers
and ABI-only reversions before the code comparison. Neither a clean textual
merge nor matching filenames proves semantic correctness.

The `*-net-state` dispositions mean that the candidate is reconciled through the
final selected subsystem, not cherry-picked unchanged. An old candidate can be
superseded within that subsystem even if its path remains modified in the port.
The per-row path policies identify retained, omitted and unchanged portions;
`result_commits` points to the actual integration/adaptation history. They must
not be interpreted as claiming that every line of an intermediate patch survives.

`reconciled-to-lts` is an affirmative decision to keep the pinned LTS file and its
fixes, with the reason recorded in that row and its path evidence. It does not
mean that the candidate has an identical upstream commit. Exact patch equivalents
have a separate disposition and stable patch-id evidence. An upstream hash in a
commit message is recorded as lineage only, unless equivalence was independently
established.

Target exclusions use the selected x86_64 goldfish product, virtual-device module
configuration, and actual SDK storage topology. They are not deductions from an
unsuccessful consumer search. Optional feature necessity and runtime limitations
are recorded in SECURITY.md. A decision to omit a separate protected-host or
physical platform is not a claim that Android never needs that platform.

## Reproduction and safety of the audit utilities

Run utilities from the Linux repository root. `inventory.py` creates a *new*
inventory and captures current project pins; **do not rerun it over the original
input pins**. `analyze.py` recreates mechanical initial classifications and does
not preserve subsequent decisions. `normalize_ack.py`, `prepare_build.py`,
`prepare_runtime.py` and `resolve.py` describe intermediate integration steps;
they are not idempotent installers for the final source and must not be run on
the finished branch.

`check_patch_presence.py` collects whole-patch textual witnesses using reverse
apply checks against temporary indexes of the pinned LTS and port trees. It
does not change source or ledger decisions. A successful check establishes that
all post-change hunks can be found; it is not a semantic or runtime proof. A
failed check is inconclusive because later edits may change the context.

`reconcile.py` refreshes the per-path blob evidence and draft net classifications
against the current committed source. `policy_text.py` contains the reviewed
source-selection rationale used by that report. `decide.py` applies explicit
reviewed overrides. Source modifications made after a report require refreshing
its evidence; the row's `code_review_head` identifies the source examined.

`check_stable_delta.py` scans all non-merge stable commits from Linux v6.18 through
the pinned LTS release that touch changed source paths. It flags both LTS-added
lines absent from the port and LTS-removed lines present again, including the
hwsim rename. These are leads for semantic review, not regression proofs. The
review must account for changed function signatures, equivalent locking helpers,
renames and deliberate security tradeoffs. This check does not establish runtime
correctness or prove that every possible semantic regression has been excluded.

`record_build.py WORKSPACE LOG --run NAME` records an already successful original
workflow, hashes its image/configuration/modules and verifies each module's
detached SHA-256 signature using the exact kernel output certificate. Run it
before changing the source checkout or starting another build. Its negative
control must reject a modified module payload. Certificate-chain trust and
in-kernel signature enforcement are not tested.
