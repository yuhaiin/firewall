# Architecture and policy semantics

The root package owns policies, validation, normalization, diagnostic evaluation,
revision management and bounded lifecycle subscriptions. Backend packages import
it, never the reverse. `native` is an optional platform selector. A `Driver` is
injectable for privilege-free lifecycle tests. No backend imports Yuhaiin.

Conditions use a tagged expression tree. Match fields specify their typed value;
unrelated populated fields are rejected. Zero-valued numbers (protocol/port/UID
zero) differ from an absent predicate. An explicit empty `All()` matches all;
a missing expression is invalid. Named zones expand expressions and have no
implicit verdict. Prefixes normalize to network boundaries. IPv4-mapped prefixes
are rejected to avoid ambiguous family semantics.

The compiler expands bounded DNF, validates every leaf and enabled term,
rejects contradictory identities/disjoint ranges, and sorts rules by priority
then ID. Each OR term becomes a native alternative; AND predicates stay in one
native filter. Native backends revalidate even direct Driver invocations. They
must reject conditions they cannot translate without widening security policy.
There are limits on input bytes, rules, nesting, expression nodes and expansion.

A policy specifies defaults per direction; absent directions have no hook.
Log continues; other actions terminate this library's rule evaluation. Explicit
state rules have normal priority. There is no hidden established/loopback/DNS
allow fast path. The caller defines safety exceptions.

`Client` serializes transactions with a context-aware gate and copies policies
into immutable owned snapshots. Reads inspect native state rather than trusting
the last desired policy. Backends enforce cross-process writer ownership and
compare generations before commits. A SHA-256 digest covers normalized policy
source; it is an identifier, not a signature or full native ruleset attestation.

Subscriptions have 64 slots, drop newest on overflow, report lost event counts
on the next delivered event, and are closed on context cancellation or client
shutdown. At most 64 concurrent subscriptions are accepted. Payloads and native
connection events are not collected in this implementation; unsupported
observability features are accurately exposed through capabilities.

Reconciliation is explicit: `Current` detects revision drift, and a new handle
recovers installed generation metadata without deleting protection. Use Reconcile with the
application's desired source to force complete native reinstallation, even if
metadata is unchanged after a native filter was externally deleted. There is no background agent silently
restoring policy against administrator intent. Revision metadata alone cannot
detect arbitrary administrator edits inside an owned table/provider.
