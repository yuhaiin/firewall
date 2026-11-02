import Foundation
import NetworkExtension
import Security

final class FilterDataProvider: NEFilterDataProvider, NSXPCListenerDelegate, FirewallControl {
    private let lock = NSLock()
    private let control = DispatchQueue(label: "firewall.snapshot")
    private var program: Program?
    private var owner = ""
    private var listener: NSXPCListener?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            let stored = try Store.read()
            let compiled = try Program(stored.snapshot)
            lock.lock(); program = compiled; owner = stored.owner; lock.unlock()
            let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
            apply(settings) { error in
                if let error = error { completionHandler(error); return }
                do {
                    let name = try Settings.string("FirewallMachService")
                    let listener = NSXPCListener(machServiceName: name)
                    listener.delegate = self
                    self.listener = listener
                    listener.resume()
                    completionHandler(nil)
                } catch { completionHandler(error) }
            }
        } catch { completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        listener?.invalidate(); listener = nil
        completionHandler()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        do {
            // Authenticate every control peer by signing identity and Team ID,
            // not PID. No network payload is sent over this connection.
            connection.setCodeSigningRequirement(try Settings.requirement(identifier: Settings.string("FirewallHostID")))
            connection.exportedInterface = NSXPCInterface(with: FirewallControl.self)
            connection.exportedObject = self
            connection.resume()
            return true
        } catch { return false }
    }

    func request(_ data: Data, reply: @escaping (Data) -> Void) {
        control.async {
            do {
                guard data.count <= 16 * 1024 * 1024 else { throw PolicyError.invalid }
                let request = try JSONDecoder().decode(Request.self, from: data)
                self.lock.lock()
                let active = self.program
                let owner = self.owner
                self.lock.unlock()
                guard owner == request.owner else { throw PolicyError.ownership }
                if request.command == "reload" {
                    let stored = try Store.read()
                    guard stored.owner == owner else { throw PolicyError.ownership }
                    guard active?.snapshot.revision == request.expected || active?.snapshot.revision == stored.snapshot.revision else { throw PolicyError.drift }
                    let replacement = try Program(stored.snapshot)
                    self.lock.lock(); self.program = replacement; self.lock.unlock()
                } else if request.command != "inspect" { throw PolicyError.unsupported }
                self.lock.lock(); let revision = self.program?.snapshot.revision; self.lock.unlock()
                guard let revision = revision else { throw PolicyError.invalid }
                reply(Response(state: NativeState(active: true, revision: revision, lifetime: "persistent")).data())
            } catch { reply(Response.failure(error).data()) }
        }
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        lock.lock(); let active = program; lock.unlock()
        guard let active = active, let socket = flow as? NEFilterSocketFlow else { return .drop() }
        let direction = flow.direction == .inbound ? "inbound" : "outbound"
        let local = socket.localEndpoint as? NWHostEndpoint
        let remote = socket.remoteEndpoint as? NWHostEndpoint
        let source = direction == "outbound" ? local : remote
        let destination = direction == "outbound" ? remote : local
        let metadata = Flow(direction: direction, ipv6: socket.socketFamily == AF_INET6,
                            source: source.flatMap { Address($0.hostname) }, destination: destination.flatMap { Address($0.hostname) },
                            sourcePort: source.flatMap { UInt16($0.port) }, destinationPort: destination.flatMap { UInt16($0.port) },
                            proto: UInt32(socket.socketProtocol), application: active.needsApplicationIdentity ? signingIdentity(flow) : nil)
        return active.allows(metadata) ? .allow() : .drop()
    }

    private func signingIdentity(_ flow: NEFilterFlow) -> String? {
        // sourceAppIdentifier is unavailable on macOS. Resolve the kernel audit
        // token through Security.framework, preserving PID-version identity.
        guard let token = flow.sourceAppAuditToken else { return nil }
        let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code = code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String else { return nil }
        return team + "." + identifier
    }
}
