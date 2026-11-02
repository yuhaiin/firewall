# Windows WFP

The 64-bit amd64/arm64 backend binds fwpuclnt.dll directly through x/sys/windows;
no CGO or driver is required. Structures match FWPM_FILTER0, FWPM_PROVIDER0,
FWPM_SUBLAYER0 and related SDK layouts, with tests for size/offsets. Native runtime
access requires an elevated administrator and a running Base Filtering Engine.
Capability permission reporting conservatively requires elevation; administrator-
modified WFP ACLs can still reject installation and will return a native error.

Config selects a stable owner and session lifetime. GUIDs derive deterministically
from a fixed namespace plus owner/object identity. A named event held for handle
lifetime excludes cooperating writers across processes without OS-thread affinity.
Provider metadata and sublayer association are checked before modification.
Never reuse another product's owner or add foreign filters to the owned provider.

ALE_AUTH_CONNECT_V4/V6 enforce outbound decisions; ALE_AUTH_RECV_ACCEPT_V4/V6
handle inbound authorization. Source/destination map to local/remote fields by
direction, not by assuming source is always local. Rules use descending explicit
64-bit weight to implement portable priority. Default filters have lowest weight.
Permit is soft; Windows Defender or another provider can still block. No firewall
product is disabled. ALE_FLOW_ESTABLISHED is not used for general permit/block.

Application predicates call FwpmGetAppIdFromFileName0 for an absolute executable
path. The executable must exist; its final long path is resolved to normalize
8.3 aliases and junctions before generating the WFP identity. User predicates require a valid SID and use ALE_USER_ID with a self-relative
security descriptor granting FWP_ACTRL_MATCH_FILTER. No PID reuse heuristic is
used. These identity formats are intentionally platform-specific.

Repeated native field predicates in one AND term are rejected because WFP can
interpret repeated fields as alternatives. Negated non-singleton port ranges and
negated user access descriptors are rejected; express complementary port ranges
with OR instead. Interface, forwarded, packet-mark, explicit conntrack, Reject,
Log, packet counters and connection event subscriptions are unsupported.

Every replacement/deletion uses an engine transaction, including provider,
sublayer and filters. Failed native validation aborts the whole transaction.
Dynamic sessions remove their objects on engine close/process exit. Persistent
policies require `PersistentService`, an installed automatic-start Windows service:
WFP may otherwise disable filters after BFE restart. The library validates the
service configuration but does not create/start services. Deployment must verify
service activation/reboot behavior. Persistent filters are not early-boot filters;
there is no guarantee before BFE starts. Lifetime changes require explicit removal
and reopening with the desired session kind.

Native tests require `FIREWALL_WFP_TEST=1` on a disposable elevated runner. They
install only application-specific blocking of the test executable's loopback
port plus soft permits. They verify DLL calls, ownership, transaction abort and
dynamic cleanup. Cross-compilation alone is not native enforcement evidence.
