import Foundation
import Darwin

// The host and extension compile this source alongside FirewallPolicy.
@objc protocol FirewallControl {
    func request(_ data: Data, reply: @escaping (Data) -> Void)
}

struct Request: Codable {
    var command: String
    var owner: String
    var expected: Revision
    var snapshot: Snapshot?
}

struct Response: Codable {
    var state: NativeState = .absent
    var available = true
    var permitted = true
    var error = ""
    var code = ""
    static func failure(_ error: Error) -> Response {
        var result = Response()
        result.error = String(describing: error)
        switch error {
        case PolicyError.ownership: result.code = "ownership"
        case PolicyError.drift: result.code = "drift"
        case PolicyError.unsupported: result.code = "unsupported"
        case PolicyError.invalid: result.code = "invalid"
        default: result.code = "unavailable"
        }
        return result
    }
    static func uncertain(_ error: Error) -> Response {
        var result = failure(error)
        result.code = "indeterminate"
        return result
    }
    func data() -> Data { (try? JSONEncoder().encode(self)) ?? Data("{\"error\":\"response encoding failed\"}".utf8) }
}

struct StoredPolicy: Codable {
    var owner: String
    var snapshot: Snapshot
}

enum Settings {
    static func string(_ key: String) throws -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String,
              !value.isEmpty, !value.contains("$(") else { throw PolicyError.invalid }
        return value
    }
    static func requirement(identifier: String) throws -> String {
        let team = try string("FirewallTeamID")
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        guard team.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              identifier.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { throw PolicyError.invalid }
        return "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
    }
}

enum Store {
    static func directory() throws -> URL {
        let group = try Settings.string("FirewallAppGroup")
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else { throw PolicyError.ownership }
        return url
    }
    static func url() throws -> URL { try directory().appendingPathComponent("firewall-v1.json") }
    static func read() throws -> StoredPolicy {
        let url = try url()
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 16 * 1024 * 1024 else { throw PolicyError.invalid }
        let data = try Data(contentsOf: url)
        let record = try JSONDecoder().decode(StoredPolicy.self, from: data)
        try record.snapshot.validate()
        return record
    }
    static func write(_ policy: StoredPolicy) throws {
        try policy.snapshot.validate()
        // The data provider only reads. Host/control components write complete
        // snapshots by atomic rename in the entitlement-protected app group.
        try JSONEncoder().encode(policy).write(to: url(), options: .atomic)
    }
}
