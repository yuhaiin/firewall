# Initial implementation review

The implementation was reviewed against the original task and the repository's
initial main commit (7b37b25), followed by a focused lifecycle recheck. Formatting,
vet/static analysis, race testing and native CI complement this source review.

## Standards

Two actionable findings were corrected: zone-only changes were missing from the
policy diff, and a failed first macOS preference save could leave orphaned
storage. Diff now reports ZonesChanged. Definite failed initial saves roll back
storage after preference readback; inactive stored revisions can also be recovered
or explicitly removed. No independent style smell required a separate refactor.

## Spec

Three initial findings were addressed: GUI-user/root app-group containers differ;
first-install failure recovery was incomplete; and metadata-only idempotence did
not restore externally removed filters. macOS now explicitly requires a root Go
client/signed host matching the system-extension UID. A normal GUI-user deployment
requires a future separately authorized privileged helper and is not claimed.
Explicit Reconcile reinstalls the complete owned policy even if its metadata digest
is unchanged. Current remains a revision observation, not an administrator-proof
attestation of every native filter.

A follow-up found that reverting storage on a lost macOS reload reply could make
live and durable revisions diverge permanently. The host now retains proposed
storage on an uncertain reply, compares live revision independently while enabled,
and reconciles either interrupted write/reload order. An unconfirmed operation
returns ErrIndeterminate. Signed macOS crash/restart behavior remains a deployment
qualification requirement; unsigned source/build review cannot establish it.
