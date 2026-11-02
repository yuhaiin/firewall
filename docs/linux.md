# Linux nftables

Requires a kernel with nf_tables, inet filtering, conntrack and requested
expression modules, plus CAP_NET_ADMIN in the target network namespace. Probe
lists tables read-only; successful probe does not guarantee every optional kernel
expression module is installed. Apply reports native errors and preserves the
old batch on kernel rejection. Netlink calls are synchronous: context is checked
before/after preparation and before commit, but cannot interrupt every blocked
kernel syscall. No shell firewall command is used in normal library operations.

Create a shared, administrator-owned private lock directory before opening:

```sh
sudo install -d -m 0700 /run/yuhaiin-firewall
```

The owner's SHA-256-derived table name starts `fw_`. An unhooked metadata chain
records version, owner, revision and lifetime. Namespaced advisory locks prevent
cooperating simultaneous writers. Use the same lock directory across clients.
Do not unlink lock files while clients are running. Existing tables with missing
or foreign metadata are refused. Initialization never flushes existing rules.
The table belongs exclusively to this owner; do not insert third-party objects
inside it. Ownership IDs should be short enough for the 256-byte marker limit.

Rules use input, output and forward inet base chains at configurable priority.
Each family is explicit before payload loads. L4PROTO resolves IPv6 extension
headers; TCP/UDP port reads use the transport header. Prefixes use native
payload/mask comparisons; OR lists of singleton addresses use a native set
lookup per family; counters are native. Interface names follow recreated
interfaces by name (not a stable hardware identity); names are exact, <=15 bytes.
Socket UID is output-only, not PID/application identity. User rules on inbound
or forwarded packets return unsupported. ICMP/ICMPv6 require explicit matching
IP family. Reject uses inet ICMPX administratively-prohibited. Log uses the kernel
log destination and is not a connection event subscription.

Replacement deletes/recreates **only the owned table in one nftables batch**.
The kernel exposes the old or the complete new ruleset; it never sees an empty
interval from those operations. Kernel rejection rolls back the entire batch.
Counters reset on replacement. `Counters` aggregates expanded alternatives by
portable rule ID. Log and overlapping OR alternatives can count a packet more
than once; these are rule-hit counters, not unique connection statistics.

Existing firewalld, UFW, Docker, iptables-nft and VPN chains remain untouched.
ACCEPT in our chain is not a global exemption: another base chain can still
DROP. A dedicated namespace test simulates another firewall's later drop chain.
Actual product-version interoperability is a separate deployment test.

Conntrack is the kernel's tracker. Explicit state predicates support NEW,
ESTABLISHED, RELATED, INVALID and UNTRACKED. No implicit allow-established rule
exists: new policy applies on the next packet, subject to host offload/capture
behavior. Dropping packets does not issue TCP resets or remove conntrack entries.
Do not promise immediate connection termination. Integration tests must account
for cached/offloaded forwarding outside these hooks in the deployment environment.

Persistent rules survive process close/crash in this network namespace, but do
not survive reboot automatically. The application/service must persist and
reapply policy early at boot. Temporary rules are removed on clean Close;
**they remain after process crash**, reported as TemporaryCrashCleanup=false.
Use explicit startup recovery/Remove rather than assuming session auto-cleanup.
`Release` closes only the ownership handle, useful after failed initialization.
There is no hidden watchdog or mandatory eBPF extension in this version.

Run native tests using `sh scripts/test-linux.sh`. The script creates a fresh
user/network namespace and checks its identity before installing rules. It never
tests against the host network namespace. Tests use `ip` only to set up isolated
test links; the library itself uses direct Netlink.
