import Foundation
import NetworkExtension

// Apple invokes a control provider where that provider configuration is
// supported. macOS system-extension updates also use acknowledged control IPC;
// correctness does not depend on the control provider being instantiated.
final class FilterControlProvider: NEFilterControlProvider {
    private var timer: DispatchSourceTimer?
    private var revision: Revision?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            revision = try Store.read().snapshot.revision
            let source = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "firewall.rules.changed"))
            source.schedule(deadline: .now(), repeating: .seconds(1))
            source.setEventHandler { [weak self] in
                guard let self = self, let next = try? Store.read().snapshot.revision, next != self.revision else { return }
                self.revision = next
                self.notifyRulesChanged()
            }
            timer = source; source.resume(); completionHandler(nil)
        } catch { completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        timer?.cancel(); timer = nil; completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow, completionHandler: @escaping (NEFilterControlVerdict) -> Void) {
        // All flow decisions stay in the data provider. The control provider
        // only supplies complete rules; no remote or per-flow policy lookup.
        completionHandler(.updateRules())
    }
}
