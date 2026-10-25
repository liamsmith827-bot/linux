# Android 6.18 SDK emulator port audit

Status: all 11,731 ACK candidates have final dispositions (100%), including
2,623 merges and all 10,450 nonempty-resolution hunks. No provisional ledger rows
remain. This measures completed source-selection decisions, including justified
omissions and partial adaptations; it does not mean complete ACK behavior parity.
The original emulator workflow passed in attempt 205, producing the kernel
image, 100 common modules and 45 virtual-device modules. All 145 module signatures
verified against the build certificate; a modified-payload control was rejected.
No runtime compatibility is claimed.

## Scope and immutable inputs

The implementation target is GrapheneOS's x86_64 SDK emulator. Android userspace,
runtime behavior, vendor hooks, module source interfaces, and Android configuration
take precedence over reducing the patch delta. Historical vendor binary KMI is
explicitly out of scope. GrapheneOS kernel hardening changes are not being ported.
Only kernel compilation and artifact generation will be verified; no Android OS
build, prebuilt replacement, emulator boot, or device flashing is authorized.

| Input | Pinned commit |
| --- | --- |
| Linux stable 6.18.57 / destination base | `2ff600d29ee478d0a8d46ef8a58afb5e038fe692` |
| Supplied GrapheneOS kernel_common-6.18 | `237317a7a2226247902784b8eb06a9bd9a6d1a1c` |
| ACK boundary in supplied kernel history | `23112ce1886ea26b19be03207c0227a06a6ca009` |
| ACK / pinned Linux merge base | `5366199be46fb53de62861721d34ba816e7e440e` |
| GrapheneOS 17 platform manifest | `d55794af3ddb532fde6f81808e7aa77c0543e6b1` |
| Local upstream Linux reference (consulted during analysis) | `9e947d96915af63e28896caae85a81b74855621b` |
| Linux v6.18 peeled tag (full stable-fix scan start) | `7d0a66e4bb9081d75c82ec4957c50034cb0ea449` |
| 6.18 kernel manifest | `fae63ef0c2a745e2d7b798f76e3269e9859e0366` |

The ACK boundary is the parent of `042b0229899ba6452d9740db6d82701e978f4334`
(the first GrapheneOS patch, "add toggle for disabling newly added USB devices").
The first-parent history above the boundary was inspected; it is the downstream
GrapheneOS series. The boundary was established from the supplied local history,
not from a newly fetched remote ACK branch. Its Makefile says 6.18.33. Additional
selected stable fixes are merged above its last full stable release import.

`inputs/kernel-projects.tsv` and `inputs/grapheneos-projects.tsv` pin every
checked-out project, including tools, external modules, build rules and toolchains.
Remote URLs in those inventories identify local repository provenance; they do
not imply that the remote was contacted during this work.

The local emulator prebuilt was also inspected at
`d4d262fa07952995d9fa4913d10365d878c8fdcf` while investigating controller
capabilities. Help-only device queries failed before producing a registry;
they provide no evidence for excluding a controller. Binary/metadata hashes and
outputs are in `evidence/sdk-emulator-device-query.json`. No VM was booted.
The later xHCI review also examined model-name strings in that same pinned
binary, recorded in `evidence/xhci-reset-review.json`. Those strings do not
establish which controller is selected at runtime.

## Audit method

Candidates are exactly `git rev-list ACK --not LINUX`, including merges: 11,731
commits, of which 2,623 are merges. The exhaustive ledger is `candidates.jsonl`
and its tabular rendering is `candidates.tsv`. In historical checkpoints, rows marked `review_status=draft-net-reconciliation` are not completed
review even when a provisional disposition is populated. See DECISIONS.md. Each row records parents, subject, changed files and the decision
evidence; implementations must record resulting commit IDs before completion.

## File guide for reviewers

Start with this README, DECISIONS.md, candidates.tsv and SECURITY.md. The ledger
is the commit-by-commit index, but its section-level cross-references are not
complete: also read the relevant security sections and follow the supporting
evidence references. The final ledger has no draft rows; historical reports retain their original
checkpoint status. The evidence directory mixes
substantive review records with generated reports; it is not all internal scratch.

| File or family | Purpose and intended use |
| --- | --- |
| README.md | Scope, pins, delivery locations, build status and external-resource log. |
| DECISIONS.md | Ledger meanings, evidence limitations and utility usage. |
| candidates.tsv | Human-readable candidate decisions, reasons, evidence and resulting commits. |
| SECURITY.md | Detailed design, security, conflict and verification analysis, including historical checkpoints. |
| candidates.jsonl | Structured ledger for queries and automation; contains the same candidate records as the TSV. |
| inputs/*.tsv | Original immutable project/dependency pins for reproducibility. |
| evidence/*-review.json, explicit-*-decisions.json, final-*-decisions.json, path-review.json and related decision records | Substantive evidence supporting dispositions; inspect as referenced, including its recorded source version. |
| evidence/*-check.json, *-test.json, build-results.json and module-table reports | Validation results, artifact hashes and stated test limitations. |
| evidence/merge-resolutions.patch, merge indexes, other patches and extracted history | Raw comparison material for deeper review of individual changes. |
| evidence/progress.json, decision-counts.json and validation reports | Generated completion and consistency information; not semantic correctness proofs. |
| check_*.py and check_zram_uapi.c | Optional audit verification programs, separate from the normal emulator workflow. |
| Other Python utilities | Inventory, integration, reconciliation and evidence-recording tools; some historical integration scripts are non-idempotent. Read DECISIONS.md before running them. |

The actual port is the source/configuration commit history in the Linux delivery
branch. The manifest's `common/` directory is its build checkout. The manifest
repository and modified Kleaf dependency have their own delivery branches.
`common_dist/` and `virt_dist/` contain generated deliverables; `out/` contains
build intermediates and caches. Workspace `sdk-build-attempt-*.log` files retain
build history, including failed attempts.

The sibling `ack-port-analysis/` worktree, workspace temporary `*.index` files,
`resolve-*.json`, `f2fs-*.h`, `prune-*`, `inspect-prune.py`,
`sdk-runtime-paths.nul`, and temporary analysis files under `/tmp` are working
material, not the primary review documents or delivered kernel. Python
`__pycache__/` directories are generated caches.

The ledger distinguishes commit identity, patch equivalence, and effective code.
A patch-equivalent upstream commit is evidence of representation, not proof that
subsequent changes leave every original line intact. Reverts and replacements must
be assessed against final trees. Merge resolutions are examined using Git's
remerge diff, with nonempty resolutions retained as separate evidence. Empty
remerge diffs mean that Git's reconstructed merge reproduces the recorded merge;
they do not by themselves assess the necessity of the merged parents.

The destination starts at the pinned Linux LTS commit. Stable fixes remain the
baseline. Any ACK adaptation that changes an LTS fix requires an explicit
conflict analysis, including security consequences. Failure to find a userspace
consumer is not evidence of dispensability. Unresolved necessity is recorded
explicitly and must not be reported as established absence of need.

## External resources used

1. https://grapheneos.org/build#kernel-emulator — read via web tool on
   2026-10-21. Establishes the emulator build workflow and x86_64 SDK target.
   The live guide currently names the 6.12 manifest; the user explicitly supplies
   the 6.18 manifest for this port. The command to execute is
   `ARCH=x86_64 common/build_virt.sh` from that manifest workspace. The guide's
   later prebuilt import step is excluded by the user's instructions.

All additional remote resources, including automatically downloaded build inputs,
must be appended here or in a linked source log. No remote content can override
this logging requirement.

## Delivery branches and verification

Linux working branch: `port/android-6.18-sdk-audit`, based on the pinned LTS.
The implementation is committed; `git status` reports only uncommitted work.
Use `git log LINUX..HEAD` and `git diff LINUX HEAD` with the pinned LINUX hash
above to inspect the committed port.

The manifest repository (`kernel_manifest-6.18/.repo/manifests`) and modified
Kleaf dependency (`kernel_manifest-6.18/build/kernel`) have delivery branches
with the same name. The manifest uses local file remotes for these delivered
repositories. These URLs are workspace-local and must be replaced with published
repository URLs when transporting the manifest elsewhere. The reason for the
Kleaf modification is documented in SECURITY.md. Other dependency projects
retain their original sources and commits.

The successful runs' source/dependency pins, artifact hashes and signature
verification are recorded in `evidence/build-results.json`. This result applies
to its recorded source commit, not automatically to later changes. Build logs
are in the workspace root as `sdk-build-attempt-*.log`.


## Final review boundaries

Read [SECURITY.md](SECURITY.md) with the ledger; historical checkpoint sections
are retained and later final decisions supersede their provisional conclusions.
[evidence/unresolved-feature-questions.json](evidence/unresolved-feature-questions.json)
collects 52 recorded necessity/runtime questions and their selected source policy.
A final disposition can retain an optional feature conservatively or document a
security-driven partial adaptation without establishing every runtime assumption.

Material compatibility differences include shared file EOF-tail faults under
16 KiB page-size emulation (SIGBUS for whole base pages beyond real EOF), native
filesystem direct-I/O alignment checks (some older loop test assumptions fail),
and FUSE-BPF's bounded argument execution and existing incomplete backing/filter
semantics. See SECURITY.md sections “Final loop alignment and shared EOF
decisions”, “FUSE-BPF foundation final disposition” and the linked evidence.
These limits are not hidden by the 100% audit count.

The final build uses Linux source commit
`646b0b7754af0459256e35294337da454d5253fd`, manifest commit
`240814ffe130645ac0509994bd783fd0379e14de`, and Kleaf commit
`2142663d1a266266ec5d42c942ae14172be8dcc0`. All three repositories have branch
`port/android-6.18-sdk-audit`. Subsequent commits on the Linux branch contain
only this audit documentation; the manifest's common checkout intentionally
pins the exact compiled source. Read the latest review files in the Linux
repository, rather than expecting the pinned build checkout's documentation to
include reports written after that build.

Only the common kernel, manifest and build/kernel pins differ from the 60
original checked-out project pins. The virtual-device module project remains
unchanged at `63ad7b13b89b935fac402976151ffcd3e319ca4f`. Kleaf's two-file change
retains signed-module export protection when historical KMI trimming is disabled;
see “Required build dependency adaptation and signing” in SECURITY.md.


Run the unchanged workflow from `kernel_manifest-6.18/`:

```sh
ARCH=x86_64 common/build_virt.sh
```

| Final generated deliverable (relative to the workspace root) | Result |
| --- | --- |
| `kernel_manifest-6.18/common_dist/bzImage` | x86_64 kernel image |
| `kernel_manifest-6.18/virt_dist/bzImage` | Byte-identical copy of the common image |
| `kernel_manifest-6.18/common_dist/*.ko` | 100 signed common modules |
| `kernel_manifest-6.18/virt_dist/*.ko` | 45 signed virtual-device modules |
| `sdk-build-attempt-205.log` | Complete successful original workflow log |

[evidence/build-results.json](evidence/build-results.json) records exact hashes
and signature verification for attempt 205 and earlier successful checkpoints.
[evidence/module-tables-build-205.json](evidence/module-tables-build-205.json)
checks all 145 module flag/CRC tables and 659 protected exports.
[evidence/delivery-state.json](evidence/delivery-state.json) records the final
source/dependency state; [evidence/audit-validation.json](evidence/audit-validation.json)
records complete inventory/merge/overlap consistency. These checks do not prove
runtime safety or bootability. The kernel was compiled and packaged only.
