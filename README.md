# firewall

Independent Go library for native system firewall policies. Module:
`github.com/yuhaiin/firewall`. No dependency on Yuhaiin, TUN stack, proxy,
configuration database, HTTP server, or frontend.

**Initial implementation, not a production-qualified security boundary.** Linux
has real enforcement tests in disposable namespaces. Windows has a native WFP
implementation and separate native CI tests. macOS has a real Swift host/system
extension and Go bridge; signing, approval, deployment and sandbox behavior need
validation on a signed installation. See [validation status](docs/validation.md).

## Backends and feature matrix

| Feature | Linux nftables | Windows WFP (64-bit) | macOS Network Extension |
|---|---|---|---|
| Enforcement | Kernel Netlink rules | Native ALE authorization layers | Native content-filter flow verdicts |
| IPv4 / IPv6; input / output | Yes | Yes | Implemented, signed deployment required |
| Forwarding | Yes | Unsupported | Unsupported |
| TCP / UDP; prefixes; port ranges | Yes | Yes | Yes, flow metadata must be available |
| Other IP protocols | Yes | ALE platform dependent | Explicitly unsupported |
| Application identity | Unsupported (no PID heuristic) | Executable WFP app ID | Source app signing identifier |
| User identity | Output socket UID | Windows SID access descriptor | Unsupported |
| Interface identity | Input / output names | Unsupported | Unsupported |
| AND / OR / NOT | Bounded normalization | Some native combinations rejected | Bounded normalization |
| Allow / Drop | Yes | Yes | Yes |
| Reject / Log | Yes (kernel log, not Events) | Unsupported | Unsupported |
| Explicit conntrack conditions | Yes | Unsupported | Unsupported |
| Rule packet / byte counters | Yes | Unsupported | Unsupported |
| Connection events | Not implemented | Not implemented | Not implemented |
| Lifecycle events / bounded subscriptions | Yes | Yes | Yes |
| Persistent | Until removal / network namespace destruction / reboot | Automatic-start service required | System-managed configuration |
| Temporary | Close cleanup; crash leaves protection installed | Dynamic session, OS crash cleanup | Unsupported |

`Capabilities` separates compiled features, runtime availability and permission.
`Current` queries native revision metadata. It does not assert that another
firewall permits the connection. Unsupported conditions return errors; they are
never silently dropped. See each platform's narrower combination restrictions.

## Architecture

Application → portable policy → validator / bounded compiler → native backend.
The portable evaluator is for diagnostics/tests; it does not intercept packets.
Linux and Windows need no CGO. macOS invokes a minimal signed root Swift host for
control operations; native providers evaluate flows using immutable local rules.
There is no Go callback per packet, routing modification, or payload collection.

## Installation and permissions

Go 1.26 or newer:

```sh
go get github.com/yuhaiin/firewall
```

- [Linux](docs/linux.md): nftables kernel support, `CAP_NET_ADMIN` in the target
  namespace, private ownership-lock directory. No `nft` CLI dependency.
- [Windows](docs/windows.md): elevated administrator and BFE; native WFP DLLs.
  Persistent policies require an installed automatic-start service.
- [macOS](docs/macos.md): Xcode, generated project, Network Extension entitlements,
  matching signing identities/app group, root host/client, system/user approval.

## Go API

This Linux example does not install default-deny or implicit safety exceptions:

```go
package main

import (
    "context"
    "log"
    "net/netip"

    fw "github.com/yuhaiin/firewall"
    "github.com/yuhaiin/firewall/native"
)

func main() {
    ctx := context.Background()
    client, err := native.Open(ctx, native.Config{
        Owner: "my-application",
        LockDir: "/run/yuhaiin-firewall", // create privately beforehand
    })
    if err != nil { log.Fatal(err) }
    defer client.Close() // persistent policy stays installed

    caps, err := client.Capabilities(ctx)
    if err != nil { log.Fatal(err) }
    log.Printf("backend=%s permitted=%t", caps.Backend, caps.Permitted)
    eventsCtx, cancel := context.WithCancel(ctx)
    defer cancel()
    events, err := client.Events(eventsCtx)
    if err != nil { log.Fatal(err) }
    go func() { for event := range events { log.Print(event.Kind) } }()

    policy := fw.Policy{
        Lifetime: fw.Persistent,
        Defaults: map[fw.Direction]fw.Action{fw.Outbound: fw.Allow},
        Rules: []fw.Rule{{
            ID: "deny-documentation-network", Priority: 100,
            Direction: fw.Outbound, Family: fw.IPv4, Action: fw.Drop,
            When: fw.Is(fw.Match{Field: fw.DestinationPrefix,
                Prefix: netip.MustParsePrefix("192.0.2.0/24")}),
        }},
    }
    if _, err = client.Apply(ctx, policy); err != nil { log.Fatal(err) }
    policy.Rules[0].When = fw.Any(policy.Rules[0].When,
        fw.Is(fw.Match{Field: fw.DestinationPrefix,
            Prefix: netip.MustParsePrefix("198.51.100.0/24")}))
    if _, err = client.Apply(ctx, policy); err != nil { log.Fatal(err) }
    // Explicitly remove only when desired: client.Remove(ctx).
}
```

[examples/basic](examples/basic) is a runnable cross-platform CLI demonstrating
capability queries, application, events, idempotent updates and safe shutdown.
Without `-apply` or `-remove`, it changes no system state. Platform-specific
`native.Config` fields are isolated from portable policies and driver interfaces.
For injectable/mocked drivers use `firewall.New(ctx, driver)`.

Rules sort by ascending priority, then ID. `All()` is an explicit wildcard;
the zero condition is invalid. `Not` uses Boolean complement across both IP
families, so NOT an IPv4 prefix also matches IPv6. Port predicates require a
positive TCP/UDP condition in every normalized branch. Defaults must be explicit;
omitted directions install no hook. Explicit default-drop requires
`AcknowledgeLockout: true` and carefully scoped management/control exceptions.
Zones expand named expressions and never grant trust by themselves.

## Lifecycle and safety

- Opening/probing does not install or flush rules.
- `Apply` validates everything before native installation; native rejection keeps
  previous enforcement. Commit acknowledgement loss can leave an **uncertain
  result**; inspect/reconcile before retrying. See [security](docs/security.md).
- `Close` releases handles and performs platform-specific temporary cleanup.
  It never deletes a persistent kill switch.
- `Remove` explicitly removes only owned enforcement. It is idempotent.
- `Reconcile` explicitly reinstalls desired enforcement even when the digest is
  unchanged. Use it to repair externally deleted rules; `Current` reads revision
  metadata and is not a full ruleset audit.
- Recovery reads native owner/generation metadata. `Current.Policy` is nil until
  desired policy is supplied again. Persist source policies in the application.
- This version has no separate disable/enable operation: replace with an explicit
  allow policy or remove enforcement deliberately. Neither changes other firewalls.

Allow is a local decision: nftables ACCEPT does not override another base chain's
DROP; WFP soft permit also coexists with other products' blocking decisions.
Never disable the host firewall to use this library.

## VPN, TUN and proxy integration

Filtering and capture/routing are separate. A capture exemption never creates a
security Allow. Linux provides masked socket-mark coordination and interface
conditions. The application owns marks/routing reservations, TUN setup, VPN
transport sockets, DNS proxying and reconnect policy. Windows/macOS use native
application identities rather than pretending to implement Linux SO_MARK.
See [loop prevention](docs/loop-prevention.md) and the independent
[Yuhaiin integration contract](docs/integration.md).

A DNS resolver in an integrating application does **not** make this a domain-aware
firewall. This project implements no DNS interception, TLS MITM or HTTP proxy.

## Development

```sh
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
sh scripts/test-linux.sh # isolated native enforcement; requires unshare and ip
go test -run '^$' -bench . -benchmem ./... # compiler/evaluator/control-plane only
```

CI runs Go tests/vet/race on Linux, Windows and macOS; cross-compiles without CGO;
executes isolated Linux and scoped Windows enforcement tests; and builds the
actual unsigned Swift/Xcode targets. Unsigned CI is not a test of signed macOS
enforcement. For native throughput use the [measurement protocol](docs/performance.md),
not compiler microbenchmark numbers.
