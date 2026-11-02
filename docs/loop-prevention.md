# Capture and enforcement are separate

This library installs no redirect, TPROXY, capture chain, route, TUN or DNS
interceptor. A firewall Allow never selects a direct route. A capture exemption
never exempts traffic from security rules. Because there is no capture path in
this library, it cannot itself recursively recapture packets.

Linux capture owners may reserve mark mask/value pairs. SetSocketMark reads the
existing SO_MARK and changes only reserved bits. Validate rejects values outside
the mask and overlap with caller-supplied other masks. It cannot discover all
external nftables/routing/cgroup mark users: inventory reservations in the
integrating application. Match marks in rules only when needed; there is no
implicit return/accept rule for marked proxy traffic.

Use TUN interface names in ingress/egress/forward rules where appropriate.
Interfaces can disappear/reappear during reconnect. Name matching follows the
name; interface renaming requires an explicit policy update. cgroup attribution,
socket cookies and universal process identity on Linux are not implemented.
Windows/macOS application identity is not an SO_MARK emulation. Route ownership
and transport reconnection stay in the host application.

## Scenario qualification matrix

| Scenario | Automated evidence | Deployment qualification still needed |
|---|---|---|
| Application → direct | Native TCP/UDP allow/drop | Physical Internet route and other firewalls |
| Application → TUN → proxy | No capture installed; marks stay subject to Drop | Actual integrating TUN/proxy capture configuration |
| Proxy socket → physical | Mark bit preservation and marked TCP denied | Policy-routing/capture exclusion on actual interface |
| VPN's own transport | Same TCP/UDP and mark conditions | WireGuard/Tailscale/GlobalProtect control channels |
| Local DNS proxy | Local UDP echo allow/drop (same transport semantics) | Resolver behavior, upstream identity and DNS routing |
| Localhost | IPv4/IPv6 real loopback TCP/UDP | Service management exceptions chosen by caller |
| LAN → VPN forwarding | Isolated routing test where available | Real VPN offload and network topology |
| IPv6 | Real loopback TCP/UDP and native family rules | Neighbor Discovery, router advertisements, tunnel MTU |
| Nested proxies | No blanket proxy/process exemption | Each hop's socket mark and destination policy |
| Reconnect / interface changes | Name predicates compile; update transactions | Real reconnect events, rename/recreation and route updates |
| Policy update with active traffic | Atomic native replacement and conntrack predicates | Existing-flow semantics differ by OS; no forced TCP teardown |
| Firewall restart with active TUN | Persistent policy recovery without initial flush | Actual live TUN deployment and startup ordering |

Do not call these unit/native transport tests a successful end-to-end VPN test.
Signed macOS, full Windows lifetime/reboot, actual VPN products, packet offload,
DHCP/ND and remote administration need isolated deployment acceptance tests.
