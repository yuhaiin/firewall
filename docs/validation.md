# Validation status

Record actual executed checks in delivery/CI rather than treating this document
as an enforcement certification. Tests are split by what they can establish:

- Common Go: validation, expression equivalence, families/order/defaults,
  unsupported predicates, rollback using a mock, serialization ownership,
  recovery, concurrent application, cancellation and bounded event overflow.
- Linux native: scripts/test-linux.sh creates a disposable namespace. Actual
  TCP/UDP IPv4/IPv6, input/output, metadata recovery, temporary Close cleanup,
  counter hits, UID/interface/mark predicates, mark bit preservation, conntrack
  NEW, kernel transaction rollback and unrelated drop-chain coexistence.
- Windows unit: SDK structure sizes/offsets and native condition compilation.
  Separate opt-in elevated CI exercises real WFP DLLs, application filtering,
  ownership, transaction abort and dynamic cleanup. Persistent service/reboot
  qualification remains a deployment task.
- macOS: Go bridge cross-build; native Swift unit tests for serialization,
  prefixes, Boolean conditions, missing metadata and unsupported fields; unsigned
  Xcode build of actual host/extension. Signed installation, app-group sandbox,
  activation/IPC, actual flow enforcement and restart/reboot remain unverified
  until executed with a provisioned developer/distribution identity.
- Benchmarks: portable compile/evaluate/diff for 100/1,000/10,000 rules, event queue,
  concurrent reads. No kernel throughput benchmark result is implied.

Real firewalld/UFW/Docker versions, full VPN/proxy/TUN integration, nested proxies,
IPv6 ND/DHCP safety policies, active-TUN process crash and physical packet
throughput are not qualified by generic loopback tests. See loop-prevention.md
for the scenario matrix and performance.md for reproducible native methodology.
