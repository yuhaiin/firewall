import Foundation
import Darwin

public struct Revision: Codable, Equatable {
    public var generation: UInt64
    public var digest: String
    public static let absent = Revision(generation: 0, digest: "")
}

public struct NativeState: Codable {
    public var active: Bool
    public var revision: Revision
    public var lifetime: String
    public static let absent = NativeState(active: false, revision: .absent, lifetime: "")
}

public struct Snapshot: Codable {
    public struct Policy: Codable { public var lifetime: String; public var defaults: [String: String] }
    public struct Rule: Codable {
        public var id: String
        public var direction: String
        public var family: String
        public var action: String
        public var terms: [[Literal]]
    }
    public struct Literal: Codable {
        public struct Match: Codable {
            public struct Ports: Codable { public var first: UInt16; public var last: UInt16 }
            public var field: String
            public var prefix: String?
            public var ports: Ports?
            public var number: UInt32?
            public var text: String?
        }
        public var match: Match
        public var not: Bool?
    }
    public var policy: Policy
    public var rules: [Rule]?
    public var revision: Revision

    public func validate() throws {
        guard policy.lifetime == "persistent", revision.generation > 0,
              revision.digest.count == 64, revision.digest.allSatisfy({ $0.isHexDigit }),
              !policy.defaults.isEmpty, (rules?.count ?? 0) <= 10000 else { throw PolicyError.invalid }
        for (direction, action) in policy.defaults {
            guard ["inbound", "outbound"].contains(direction), ["allow", "drop"].contains(action) else { throw PolicyError.unsupported }
        }
        var count = 0
        for rule in rules ?? [] {
            guard policy.defaults[rule.direction] != nil, ["ipv4", "ipv6", "dual"].contains(rule.family),
                  ["allow", "drop"].contains(rule.action), !rule.terms.isEmpty else { throw PolicyError.invalid }
            count += rule.terms.count
            guard count <= 100000 else { throw PolicyError.invalid }
            for term in rule.terms {
                guard term.count <= 256 else { throw PolicyError.invalid }
                for literal in term {
                    let m = literal.match
                    switch m.field {
                    case "protocol": guard [6, 17].contains(m.number ?? 0) else { throw PolicyError.unsupported }
                    case "source_prefix", "destination_prefix": _ = try Prefix(m.prefix ?? "")
                    case "source_port", "destination_port":
                        guard let ports = m.ports, ports.first <= ports.last,
                              term.contains(where: { $0.match.field == "protocol" && $0.not != true && [6, 17].contains($0.match.number ?? 0) }) else { throw PolicyError.invalid }
                    case "application": guard !(m.text ?? "").isEmpty else { throw PolicyError.invalid }
                    default: throw PolicyError.unsupported
                    }
                }
            }
        }
    }
}

public enum PolicyError: Error { case invalid, unsupported, drift, ownership, missingMetadata }

// Address parsing uses numeric IPs only. No DNS queries occur in the provider.
public struct Address {
    public var bytes: [UInt8]
    public init?(_ text: String) {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 { bytes = withUnsafeBytes(of: &v4) { Array($0) }; return }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 { bytes = withUnsafeBytes(of: &v6) { Array($0) }; return }
        return nil
    }
}

public struct Prefix {
    let address: Address
    let bits: Int
    public init(_ text: String) throws {
        let parts = text.split(separator: "/")
        guard parts.count == 2, let addr = Address(String(parts[0])), let width = Int(parts[1]),
              width >= 0, width <= addr.bytes.count * 8 else { throw PolicyError.invalid }
        address = addr; bits = width
    }
    public func contains(_ candidate: Address) -> Bool {
        guard address.bytes.count == candidate.bytes.count else { return false }
        for i in 0..<bits { let mask = UInt8(1 << (7 - i % 8)); if address.bytes[i / 8] & mask != candidate.bytes[i / 8] & mask { return false } }
        return true
    }
}

public struct Flow {
    public var direction: String
    public var ipv6: Bool
    public var source, destination: Address?
    public var sourcePort, destinationPort: UInt16?
    public var proto: UInt32
    public var application: String?
    public init(direction: String, ipv6: Bool, source: Address?, destination: Address?, sourcePort: UInt16?, destinationPort: UInt16?, proto: UInt32, application: String?) {
        self.direction = direction; self.ipv6 = ipv6; self.source = source; self.destination = destination
        self.sourcePort = sourcePort; self.destinationPort = destinationPort; self.proto = proto; self.application = application
    }
}

// Program pre-parses prefixes at snapshot load. Native flow callbacks perform
// no file access, synchronous IPC, DNS lookup, or Go evaluation.
public final class Program {
    public let snapshot: Snapshot
    public let needsApplicationIdentity: Bool
    private var prefixes: [String: Prefix] = [:]
    public init(_ snapshot: Snapshot) throws {
        try snapshot.validate(); self.snapshot = snapshot
        needsApplicationIdentity = (snapshot.rules ?? []).contains { rule in rule.terms.contains { term in term.contains { $0.match.field == "application" } } }
        for rule in snapshot.rules ?? [] { for term in rule.terms { for literal in term {
            if let text = literal.match.prefix { prefixes[text] = try Prefix(text) }
        } } }
    }
    private func match(_ literal: Snapshot.Literal, _ flow: Flow) -> Bool? {
        let m = literal.match
        let result: Bool?
        switch m.field {
        case "protocol": result = flow.proto == (m.number ?? 0)
        case "source_prefix": result = flow.source.map { prefixes[m.prefix ?? ""]!.contains($0) }
        case "destination_prefix": result = flow.destination.map { prefixes[m.prefix ?? ""]!.contains($0) }
        case "source_port": result = flow.sourcePort.map { $0 >= m.ports!.first && $0 <= m.ports!.last }
        case "destination_port": result = flow.destinationPort.map { $0 >= m.ports!.first && $0 <= m.ports!.last }
        case "application": result = flow.application.map { $0 == m.text }
        default: return nil
        }
        return result.map { literal.not == true ? !$0 : $0 }
    }
    public func allows(_ flow: Flow) -> Bool {
        for rule in snapshot.rules ?? [] {
            if rule.direction != flow.direction || (rule.family == "ipv6" && !flow.ipv6) || (rule.family == "ipv4" && flow.ipv6) { continue }
            var unknown = false
            for term in rule.terms {
                var failed = false, missing = false
                for literal in term { if let result = match(literal, flow) { if !result { failed = true; break } } else { missing = true } }
                if !failed && !missing { return rule.action == "allow" }
                if !failed && missing { unknown = true }
            }
            // Unknown metadata must never turn a security predicate (including
            // NOT) into an implicit permission. Conservative flow denial.
            if unknown { return false }
        }
        return (snapshot.policy.defaults[flow.direction] ?? "allow") == "allow"
    }
}
