# Versioned skill collection

`collect-skill-inventory` is a read-only local inspection command. It does not
upload, modify Claude configuration, replace the installed gateway, or enforce a
policy. Existing `scan-inventory`, routing and proxy behavior are unchanged.

## Sources and evidence

| Source | What establishes presence | Limits |
| --- | --- | --- |
| Claude Code user/project standalone skills | `skills/*/SKILL.md` | Presence does not prove enabled state |
| Claude Code installed plugins | Bounded `installed_plugins.json` plus an existing skill package under the plugin root | External install paths, ambiguous paths, missing/malformed manifests are incomplete coverage; publisher names establish no trust |
| Plugin and marketplace caches | Recognized cache directory layouts | Labeled cached; manifest-confirmed installations excluded from cache rows |
| Cowork persistent plugins | Packages under `local-agent-mode-sessions/skills-plugin` | Enabled state remains unknown |
| Cowork session copies | `*/*/local_*/.claude/skills/*/SKILL.md` | Session identity and lifecycle are distinct from persistent installation |
| Cowork session uploads | `*/*/local_*/uploads/SKILL.md` | Only this file is read. Unrelated upload files and transcripts are not scanned; no full-package digest or complete package assessment is claimed |
| Account-only skills | None | Explicitly unsupported |

Root and location identities are opaque SHA-256 metadata. No absolute path,
source content, matched credential value, account database or transcript is
emitted. Skill and plugin names remain visible inventory metadata. These IDs
are not proof of publisher authenticity or immutable invocation-time identity.

## Bounded traversal and resumption

The pass has a ten-second context deadline, 12,000 enumerated entries, 1,000
observations, depth eight, 1,000 assessed files, 2 MiB per file, and 20 MiB total
assessed bytes. OS-level blocking I/O cannot be forcibly interrupted by a Go
context; the coordinator still needs a process watchdog. Known path components
are opened directly, so unrelated session files do not consume enumeration
budget. All recognized package locations are enumerated before assessment.

Traversal is relative to retained directory descriptors, with no-follow opens.
Source roots remain anchored under the requested user/project root. Package
replacement between enumeration and assessment is rejected. Symlinks are not
silently followed or treated as clean absence. Missing/unreadable sources are
unavailable, and incomplete enumeration is partial. Neither permits removal
inference. Assessment completeness is independent from source completeness.

`CollectV2FromCursor` returns `NextAssessmentOffset`. A coordinator must retain
that cursor between passes; otherwise a large first package could continually
starve later assessments. The local command accepts `--assessment-offset` for
resumption testing. A full digest is produced only for a complete readable
package manifest; assessment findings use the full-package assessor documented
in `skill-package-assessment.md`. Unknown and partial results never become Low.

## Wire compatibility

`ChunkCollection` emits the web v2 envelope: at most 200 observations and 1 MiB
of compact JSON per chunk, at most 50 chunks, the same source list throughout,
and caller-supplied epoch/sequence/scan identity. No observations or findings are
silently dropped to fit a transport limit. `--wire-preview` generates ephemeral
IDs for local validation only; it neither uploads nor advances durable state.

The web contract is `contracts/skill-inventory-v2.schema.json` in
`agentkeeper-web`; its runtime Zod validator also checks semantic consistency.
Metadata remains independent from the legacy preview-based inventory channel.

## Validation

Unit fixtures exercise all source classes, distinct same-name packages, session
upload privacy, manifest identity, forged publisher prefixes, source/package
symlinks, package replacement, cancellation, partial coverage, cursor fairness,
and chunk byte/record limits. Existing gateway tests and race checks pass;
Windows cross-compilation preserves explicit unsupported v2 assessment behavior.

On the development Mac, a read-only scan found 437 observations: 73 persistent
plugin observations, 38 cache observations, six Cowork session copies and 320
Cowork session uploads. The original enumeration exhausted its entry budget;
direct opening of known path components fixed that gap. Three resulting chunks
passed the web runtime validator. A resumed pass assessed all 320 uploaded
`SKILL.md` files and retained all 320 file hashes, while correctly producing zero
full-package digests for uploads. Only aggregate results are retained here.

## Still required before rollout

This change is a collector foundation. It does not enable recurring reporting,
watchers, device-authenticated transport, durable epoch/sequence/cursor/spool
state, acknowledgement recovery, UI projections, notifications, approved-version
grants, or blocking. Those need the native coordinator, server feature gate and
end-to-end proof described in the product PRD. Symlink-based sources and
unrecognized layouts remain explicit coverage gaps, not certified support.

## Rapid change hints

`collect-skill-inventory --metadata-only` and the public `Probe` function enumerate
recognized locations with a two-second context budget. They read bounded plugin
manifests and SKILL.md filesystem metadata, never skill bodies. A stable opaque
fingerprint lets the native coordinator debounce installs and SKILL.md changes
without opening thousands of persistent filesystem watches. Atime is excluded
so assessment reads do not trigger an endless scan loop. Incomplete enumeration
cannot emit a usable fingerprint. Probe results cannot be chunked or uploaded as
authoritative inventory.

This is a scheduling hint, not package identity or tamper-proof monitoring.
Resource-only edits are found by periodic full-package assessment. No immediate
resource-change or invocation-time enforcement guarantee is made by this probe.

## Priority assessment for background native consumers

`skillinventory.CollectWithAssessmentHints` accepts the saved assessment cursor, up to 1,000 opaque local hints, and an explicit priority-pass switch. New or changed SKILL.md metadata is assessed before unchanged candidates on a priority pass, within the existing shared file, byte, and time budgets. Scanner-version changes invalidate the hints. Resource-only changes still require periodic full collection.

The result returns `AssessmentHints`, `PriorityApplied`, and `AssessmentPending` as local scheduling state. These fields are deliberately excluded from inventory envelopes. A hint records a stable bounded assessment attempt, including a partial assessment; it is neither a package digest, a safety verdict, nor an approval. Changed/unavailable/deadline reads remain eligible for retry. Unassessed changes keep their previous hint and cannot be mistaken for completed work.

The ordinary cursor advances only across candidates actually visited at that cursor. If a large new package exhausts a priority pass, the normal cursor is preserved. Consumers must follow a priority-applied pass with an ordinary pass and retain state across restarts. Pending changes and the follow-up ordinary pass should use the existing bounded background catch-up cadence; completed work returns to periodic reconciliation. This API does not run on the tool invocation path and does not change the older Collect/Probe/Chunk contracts.

Validation includes new and modified malicious skills behind an unchanged 1,000-file package, preservation of the normal cursor after a large priority package, pending-change retention, invalid/oversized hint rejection, transport exclusion, and the complete gateway race suite. Native scheduling, signed artifact publication, installed service behavior and end-to-end discovery latency require separate acceptance.
