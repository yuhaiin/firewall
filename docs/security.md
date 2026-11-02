# Security model, failure behavior and limits

This initial version requires deployment review before security-critical use.
Administrator/root can modify native objects or stop enforcement; metadata is
not an attestation. App-group membership and signing entitlements are part of the
macOS trust boundary. Lock directories must be private and shared consistently.
Locks coordinate this library's writers, not arbitrary administrative tools.

| Trigger | Defined behavior |
|---|---|
| Backend unavailable or permission denied at startup | Return error; install/remove nothing |
| Invalid/unsupported policy | Return error before transaction; old enforcement remains |
| Native policy rejection | Abort native transaction; old enforcement remains |
| Lost commit acknowledgement / helper crash | Outcome can be uncertain; inspect/reopen/reconcile before retrying |
| Main process crash | Linux rules remain; dynamic WFP is removed by OS; persistent WFP and macOS configuration remain |
| macOS provider crash | OS manages restart; no claim of guaranteed blocking during restart |
| Corrupt native metadata | Refuse ownership/recovery, do not flush protection |
| Corrupt macOS replacement snapshot | Keep the current valid program; report load error |
| Corrupt macOS snapshot on provider restart | Fail startup; OS restart/failure behavior requires signed qualification |
| System restart | Linux requires early service reapply; WFP persistent needs auto-start service/BFE; macOS system-managed |
| Slow event consumer | Bounded drop-newest queue, loss count; no unbounded payload/state buffer |

There is no ambiguous fail-open/fail-closed switch. Default-deny with explicit
lifetimes is available, but is **not** a claim of end-to-end fail-closed behavior
across boot gaps, kernel offload, service shutdown, or native-extension crashes.
Those guarantees require deployment-specific startup and crash testing. Temporary
Linux protection lingering after a crash is intentional protection retention,
not a session-lifetime guarantee.

No automatic safety Allow exists. Before default-deny, explicitly decide on
loopback, DHCP, DNS, IPv6 Neighbor Discovery, LAN management, SSH/RDP and VPN
transport/control. Prefix/port Allow exceptions must be scoped to actual
interfaces/identities/destinations. AcknowledgeLockout is an explicit API guard,
not proof that remote administration remains reachable. Test policies in a
namespace/VM and maintain an out-of-band recovery channel.

Logging uses kernel facilities on Linux. Connection observation and native
failure-stream subscriptions are not implemented; do not infer them from an
Events channel. The channel reports lifecycle/API errors only. Traffic counters
are native rule hits, reset on replacement, and are not unique-flow statistics.

IPv6 fragmentation, route offload, containers, bridged traffic outside IP hooks,
other WFP arbitration, and unavailable Network Extension flow metadata must be
reviewed against real deployment. macOS missing metadata is conservatively denied
when it could affect a rule; NOT never converts unknown identity/address into an
Allow. No payload inspection or domain-name policy resolution is implemented.

Native cancellation is checked before commit; it cannot undo an acknowledged
commit or reliably interrupt every synchronous OS call. The application must
inspect state after ambiguous errors. Current revision drift is explicit; recover
using a new owner handle and the stored desired policy rather than overwriting
another generation blindly.
