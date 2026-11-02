# Integration contract with Yuhaiin

Import `github.com/yuhaiin/firewall` for portable policies and
`github.com/yuhaiin/firewall/native` (or an explicit backend) for initialization.
Use a version pinned to a reviewed commit/tag until the API stabilizes. Create
one owner per independently managed policy and keep the handle for its lifetime.
`native.Open(ctx, native.Config{...})` probes and recovers without installing rules.
Platform config varies; portable Policy/Rule/Condition and Firewall stay reusable.

Yuhaiin owns high-level business rules, configuration storage, routes, VPN/TUN
configuration, transparent capture, socket creation, proxy transports, user
credentials, DNS resolution, UI/API and authentication. Map its decisions to an
explicit complete firewall policy; do not pass pointers into mutable app state.
The firewall module imports none of those packages and does not modify Yuhaiin.

The library owns policy normalization, native rule compilation, owned object
installation/lifecycle, capability reporting, revision state/recovery and bounded
lifecycle events. Backend optional APIs expose actual native rule counters or
socket-mark coordination; unavailable connection attribution is not fabricated.

Suggested startup: initialize routes/control sockets in the app; open/query
firewall capability and native Current state; compare against stored desired
policy; compile/apply the complete source; subscribe to lifecycle events. A
startup error is an error, not an instruction to remove the last kill switch.
The application decides whether to start other networking after that error.

For Linux proxy transport sockets, reserve mark bits with the route/capture
owner and set only those bits before connect/send using linux.SetSocketMark.
Capture ignores those marked sockets; security policy still sees them and can
drop forbidden destinations. Mark reservations must include other consumers'
masks supplied by the application. No automatic global reservation registry exists.
On Windows use a native app ID/executable condition; on macOS use the signed source
app identity. Neither means unconditional trust of the proxy process.

On shutdown close the handle; retain persistent policy. Explicitly call Remove
only when the user/application intends to remove protection. Persist desired
source outside this module and reapply on reboot as documented for the OS.
`ErrDrift` requires explicit recovery/reconciliation, not a silent global flush.
An integration UI must disclose default-deny impact before setting
AcknowledgeLockout, and expose actual errors/capabilities instead of claiming a
rule is effective because a configuration record exists.
