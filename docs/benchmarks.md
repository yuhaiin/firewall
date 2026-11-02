# Executed benchmark baseline

Executed on 2026-11-02 with Go 1.27.3, linux/amd64, AMD Ryzen 5 5600G,
GOMAXPROCS=12. One short run (`-benchtime=100ms -count=1`) provides a reproducible
initial control-plane baseline, not a statistical performance comparison.

```sh
go test -run '^$' -bench . -benchmem -benchtime=100ms -count=1 ./...
```

| Operation | 100 rules | 1,000 rules | 10,000 rules |
|---|---:|---:|---:|
| Compile | 0.293 ms | 3.050 ms | 32.251 ms |
| Compile allocation | 127,052 B | 1,974,714 B | 24,880,102 B |
| Compile allocations | 546 | 5,098 | 50,397 |
| Portable worst-case Evaluate | 1.600 us | 15.640 us | 162.462 us |
| Evaluate allocation | 0 B | 0 B | 0 B |
| Diff | 0.211 ms | 2.123 ms | 21.977 ms |

Lifecycle event publish+receive: 77.30 ns/op, 0 B/op, 0 allocations/op.
Concurrent policy reads mixed with one update per 16 operations: 6.267 us/op,
1,139 B/op, 13 allocations/op. These include synchronization and policy copies.

The portable evaluator is diagnostic Go code. None of these numbers is a kernel
packet-throughput measurement. Run longer repeated benchmarks and benchstat when
comparing future changes; retain toolchain, CPU and workload details.

## Native evidence

`sh scripts/test-linux.sh` successfully installed 100, 1,000 and 10,000 real rules
in an isolated namespace. At 10,000 rules the kernel could overflow ACK buffering
after committing. Atomic generation-marker readback confirms the installed batch
and prevents incorrectly reporting a rollback or reapplying blindly.

The following native harness smoke command also completed all 16 combinations:

```sh
FIREWALL_BENCH_SECONDS=1 FIREWALL_BENCH_REPEATS=1 bash scripts/bench-linux.sh
```

This uses a separate client, router and server namespace; actual IPv4/IPv6 TCP and
UDP traverse two veth links and the router's nftables forward hook. Counts are
0/100/1,000/10,000 unmatched rules, mixed across IP families. Iperf3 client/server
JSON and environment data are saved under a newly created ignored
`firewall-benchmark-results.*` directory. All 16 JSON client results were parsed
and checked for errors. The short runs qualify harness operation only; use the
full repeated methodology in performance.md for publishable throughput results.
