# macOS Network Extension

The implementation uses a Swift host application and a real system extension
with NEFilterDataProvider. NEFilterControlProvider and handleRulesChanged are
explicitly unavailable in the macOS SDK; the signed host supplies the control
role through the declared authenticated Mach endpoint. The Go backend
executes the signed host only for control operations. No PF fallback, KEXT, TUN,
per-packet Go callback, or remote flow decision is used.

## Build and signing

Requirements: macOS 13+, Xcode/command-line tools, XcodeGen, an Apple Developer
team with content-filter Network Extension approval and suitable provisioning
profiles/certificates. Bundle identifiers/app groups must be registered for that
team. Do not assume an unsigned binary or arbitrary command-line executable can
activate a system extension. Set these build values for your distribution:

- DEVELOPMENT_TEAM (no team/signing credentials are hardcoded).
- FIREWALL_HOST_ID / FIREWALL_EXTENSION_ID.
- FIREWALL_APP_GROUP, consistently granted to host and extension. On macOS the
  default uses TeamIdentifierPrefix plus an identifier; configure your actual
  provisioned app group rather than reusing an unrelated app's container.
- FIREWALL_MACH_SERVICE, consistent with NetworkExtension.NEMachServiceName.

```sh
brew install xcodegen
xcodegen generate --spec native/darwin/project.yml
xcodebuild -project native/darwin/Firewall.xcodeproj -scheme FirewallHost \
  -configuration Debug -derivedDataPath native/darwin/build \
  DEVELOPMENT_TEAM=YOUR_TEAM_ID build
swift test --package-path native/darwin/PolicyKit
```

CI builds the actual targets with CODE_SIGNING_ALLOWED=NO. This checks source and
packaging, **not** entitlements, sandbox enforcement or successful installation.
Inspect the embedded Contents/Library/SystemExtensions bundle and sign the
extension/host with matching team requirements. Developer ID distribution also
requires the appropriate profiles, hardened runtime and notarization; consult
[Apple's system extension deployment documentation](https://developer.apple.com/system-extensions/).

This version requires the Go client and signed control host to run as root.
System extensions run as root and app-group containers are per-user, so a GUI-user
host would write to a different container. The API rejects that deployment rather
than assuming containers are shared across UIDs. A GUI integration needs a
separately authorized privileged helper; this repository does not install one.
See [Apple DTS on container identity](https://developer.apple.com/forums/thread/133761).

Install FirewallHost.app under /Applications. From its Contents/MacOS executable,
submit an explicit activation request (GUI login session required):

```sh
printf '%s' '{"command":"activate","owner":"firewall-example","expected":{"generation":0,"digest":""}}' \
  | sudo /Applications/FirewallHost.app/Contents/MacOS/FirewallHost
```

Approve the extension and content filter when macOS requests it. Some upgrades
require reboot. Set FIREWALL_HOST_EXECUTABLE to that absolute executable path and
FIREWALL_LOCK_DIR to an existing private directory before running examples/basic.
Do not activate an unsigned CI artifact. Use a VM or dedicated test device.

`deactivate` explicitly requests system-extension deactivation; first call Remove
to remove the owned filter configuration. OS policy can require approval/reboot.
The helper never disables another product's content filter.

## Snapshots and enforcement

The signed host/control side writes a complete validated snapshot by atomic
rename in the entitlement-protected app group. The data provider reads only this
location, pre-parses prefixes, and swaps an immutable native program under a short
lock. The data provider performs no disk read, network request or synchronous IPC
on the flow decision path. OS content-filter verdicts perform enforcement.

Control IPC uses the extension's declared Mach service, authenticated by code
signing requirement (host identifier + Team ID + Apple trust anchor). The host
also validates the extension peer. No PID-based application policy is used. IPC
carries only control commands/revisions; no packet payload or flow content leaves
the provider. Signed deployment must validate that this declared control endpoint
and app-group reads are allowed under the actual OS sandbox/provisioning profile.
Updates use acknowledged snapshot-reload IPC; the unavailable iOS control-provider
API is not declared in the macOS extension manifest.

Apply waits for the data provider's active revision reply. A file write/preferences
save alone never returns successful installation. If activation/IPC fails, an
error is returned; prior valid stored policy is retained/restored when possible.
A helper/acknowledgement failure is an ambiguous commit, not proof that no policy
changed: inspect/reconcile. Existing allowed flows are not forcibly terminated
on policy update. New-flow decisions use the current complete program.

TCP/UDP inbound/outbound flow policies, numeric IPv4/IPv6 prefixes, ports and source
app signing identifier are supported in source. Missing endpoints/identity can
prevent precise rule matching; potentially relevant unknown metadata is denied.
Only persistent/system-managed lifetime is available. Forwarding, packet marks,
interface/UID conditions, ICMP-specific policy, Reject, Log, counters and native
connection event streaming are explicitly unsupported. Non-socket flows are denied
by this content-filter implementation. The OS does not guarantee packet-level
parity with nftables or fail-closed behavior during extension crash/restart.

## Signed acceptance procedure

Build/install/approve using your actual team. Apply an allow policy first; query
Current and compare the provider reply revision. Test targeted TCP/UDP drops with
IPv4 and IPv6, application identity including missing-identity behavior, snapshot
replacement, provider restart, corrupt storage, user revocation, sleep/wake,
reboot, and another content filter. Remove the policy and deactivate deliberately.
Validate IPC rejection from an unrelated signed process and group isolation.
Keep a management recovery channel. None of these signed acceptance steps is
claimed to be verified by unsigned CI or Linux cross-compilation.
