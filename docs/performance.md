# Performance measurement

`go test -run '^$' -bench . -benchmem ./...` benchmarks compilation, portable
worst-case matching, policy diff, concurrent policy reads and event queue delivery.
Compilation/matching/diff cases cover 100, 1,000 and 10,000 rules. These are Go
control-plane/diagnostic costs, **not kernel packet throughput**. The evaluator
is linear and intentionally not used for OS packet filtering. No implicit
user-space packet copies or unbounded per-connection maps are introduced.

For a native throughput result, use an isolated VM pair or disposable Linux
network-namespace router with two veth peers. Run iperf3 TCP and UDP for IPv4 and
IPv6, record kernel/OS versions, CPU pinning, NIC/offload/MTU, rule counts, flow
counts, conntrack, matching position and traffic direction. Measure baseline,
100/1,000/10,000-rule allow-last and drop-target policies, bidirectional load,
packet/byte throughput, p50/p99 latency, CPU and retransmissions. Use at least five
30-second runs with warmup and report variance. Repeat with conntrack and any
hardware/offload behavior explicitly described. Never run a default-deny or
routing benchmark against the developer's host namespace.

Windows needs a dedicated elevated VM and the actual ALE layers/app identities;
macOS needs the signed/approved extension and controlled flows. Compiler timings,
loopback transport checks and unsigned builds are not substitutes for these
measurements. No native packet-throughput result is claimed in this version.
