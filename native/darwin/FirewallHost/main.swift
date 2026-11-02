import Foundation
import NetworkExtension
import SystemExtensions

func finish(_ response: Response) -> Never {
    FileHandle.standardOutput.write(response.data())
    exit(0)
}

final class Activation: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        FileHandle.standardError.write(Data("Approve the system extension in System Settings.\n".utf8))
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .willCompleteAfterReboot { finish(Response.failure(NSError(domain: "firewall", code: 1, userInfo: [NSLocalizedDescriptionKey: "Activation requires a restart"]))) }
        finish(Response())
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish(Response.failure(error)) }
}

final class Host {
    let manager = NEFilterManager.shared()
    let request: Request
    var connection: NSXPCConnection?
    var activation: Activation?
    var storageLock: Int32 = -1
    init(_ request: Request) { self.request = request }

    func start() {
        do {
            let lockURL = try Store.directory().appendingPathComponent("firewall-control.lock")
            storageLock = open(lockURL.path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
            guard storageLock >= 0, flock(storageLock, LOCK_EX | LOCK_NB) == 0 else { throw PolicyError.ownership }
            if ["activate", "deactivate"].contains(request.command) {
                let id = try Settings.string("FirewallExtensionID")
                let operation = request.command == "activate" ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: id, queue: .main) : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: id, queue: .main)
                let delegate = Activation(); activation = delegate; operation.delegate = delegate
                OSSystemExtensionManager.shared.submitRequest(operation); return
            }
            manager.loadFromPreferences { error in
                if let error = error { finish(Response.failure(error)) }
                self.loaded()
            }
        } catch { finish(Response.failure(error)) }
    }

    func rpc(_ command: String, completion: @escaping (Response) -> Void) {
        do {
            let name = try Settings.string("FirewallMachService")
            let conn = NSXPCConnection(machServiceName: name, options: .privileged)
            conn.setCodeSigningRequirement(try Settings.requirement(identifier: Settings.string("FirewallExtensionID")))
            conn.remoteObjectInterface = NSXPCInterface(with: FirewallControl.self)
            conn.resume(); connection = conn
            guard let proxy = conn.remoteObjectProxyWithErrorHandler({ error in completion(.failure(error)) }) as? FirewallControl else { throw PolicyError.invalid }
            var message = request; message.command = command; message.snapshot = nil
            proxy.request(try JSONEncoder().encode(message)) { data in
                do { completion(try JSONDecoder().decode(Response.self, from: data)) }
                catch { completion(.failure(error)) }
            }
        } catch { completion(.failure(error)) }
    }

    func loaded() {
        do {
            let expectedID = try Settings.string("FirewallExtensionID")
            if let existing = manager.providerConfiguration {
                guard existing.filterDataProviderBundleIdentifier == expectedID,
                      existing.vendorConfiguration?["owner"] as? String == request.owner else { throw PolicyError.ownership }
            }
            if request.command == "probe" {
                // Loading preferences demonstrates entitlement access. Runtime
                // activation is checked by inspect/apply and never fabricated.
                _ = try Settings.requirement(identifier: expectedID)
                finish(Response())
            }
            if request.command == "inspect" {
                if !manager.isEnabled {
                    if FileManager.default.fileExists(atPath: try Store.url().path) { throw PolicyError.drift }
                    finish(Response())
                }
                rpc("inspect", completion: finishResponse); return
            }
            if request.command == "remove" {
                if !manager.isEnabled && manager.providerConfiguration == nil {
                    guard request.expected == .absent else { throw PolicyError.drift }
                    if let orphan = try? Store.read() {
                        guard orphan.owner == request.owner else { throw PolicyError.ownership }
                        try FileManager.default.removeItem(at: Store.url())
                    }
                    finish(Response())
                }
                // Explicit removal must remain possible when the provider is
                // restarting or cannot answer IPC. Compare owned stored state.
                let stored = try Store.read()
                guard stored.owner == request.owner else { throw PolicyError.ownership }
                guard stored.snapshot.revision == request.expected else { throw PolicyError.drift }
                    self.manager.removeFromPreferences { error in
                        if let error = error { finish(.failure(error)) }
                        do { let url = try Store.url(); if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }; finish(Response()) }
                        catch { finish(.failure(error)) }
                    }
                }; return
            }
            guard request.command == "replace", let snapshot = request.snapshot else { throw PolicyError.unsupported }
            try snapshot.validate()
            let previous = try? Store.read()
            if let previous = previous { guard previous.owner == request.owner else { throw PolicyError.ownership } }
            guard (previous?.snapshot.revision ?? .absent) == request.expected else { throw PolicyError.drift }
            if manager.isEnabled {
                rpc("inspect") { response in
                    guard response.error.isEmpty, response.state.revision == self.request.expected else { finish(response.error.isEmpty ? .failure(PolicyError.drift) : response) }
                    self.install(snapshot, previous: previous)
                }
            } else { install(snapshot, previous: previous) }
        } catch { finish(.failure(error)) }
    }

    func install(_ snapshot: Snapshot, previous: StoredPolicy?) {
        do {
            try Store.write(StoredPolicy(owner: request.owner, snapshot: snapshot))
            let reload = {
                self.rpc("reload") { response in
                    if !response.error.isEmpty {
                        // Do not delete or disable existing protection on IPC
                        // failure. The result may be ambiguous after a crash;
                        // callers must Inspect/reconcile before retrying.
                        if let previous = previous { try? Store.write(previous) }
                    }
                    finish(response)
                }
            }
            if manager.isEnabled { reload(); return }
            let config = NEFilterProviderConfiguration()
            config.filterSockets = true; config.filterBrowsers = false
            config.filterDataProviderBundleIdentifier = try Settings.string("FirewallExtensionID")
            config.vendorConfiguration = ["owner": request.owner]
            manager.providerConfiguration = config
            manager.localizedDescription = "Firewall policies"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error = error {
                    do { try self.rollbackStorage(previous) }
                    catch { finish(.failure(error)) }
                    finish(.failure(error))
                }
                // Initial activation can need user approval. Retry is bounded;
                // Apply never returns success without the data-provider reply.
                DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: reload)
            }
        } catch { finish(.failure(error)) }
    }

    func rollbackStorage(_ previous: StoredPolicy?) throws {
        if let previous = previous { try Store.write(previous) }
        else {
            let url = try Store.url()
            if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
        }
    }
}

func finishResponse(_ response: Response) { finish(response) }

do {
    // System extensions run as root. App-group containers are per-user, so this
    // deployment deliberately requires the signed control host to run as root.
    // A future GUI-user integration needs a separately approved root helper.
    guard geteuid() == 0 else { throw NSError(domain: "firewall", code: 13, userInfo: [NSLocalizedDescriptionKey: "Run the signed host as root; per-user app-group containers cannot share system policy"]) }
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count <= 16 * 1024 * 1024 else { throw PolicyError.invalid }
    let request = try JSONDecoder().decode(Request.self, from: input)
    guard !request.owner.isEmpty else { throw PolicyError.invalid }
    let host = Host(request)
    host.start()
    RunLoop.main.run()
    withExtendedLifetime(host) {}
} catch { finish(.failure(error)) }
