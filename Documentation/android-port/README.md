# Android 6.18 SDK emulator port audit

Status: work in progress. The complete emulator workflow succeeded in attempt 121
at Linux f6617750f7d3, including final signing. All 145 generated module signatures
were cryptographically verified against the build certificate; a modified-payload
control was rejected. The exhaustive commit audit remains unfinished. No runtime compatibility is claimed.

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

## Audit method

Candidates are exactly `git rev-list ACK --not LINUX`, including merges: 11,731
commits, of which 2,623 are merges. The exhaustive ledger is `candidates.jsonl`
and its tabular rendering is `candidates.tsv`. Rows marked `review_status=draft-net-reconciliation` are not completed
review even when a provisional disposition is populated. See DECISIONS.md. Each row records parents, subject, changed files and the decision
evidence; implementations must record resulting commit IDs before completion.

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
