import XCTest
@testable import FirewallPolicy

final class PolicyTests: XCTestCase {
    func snapshot(_ terms: String) throws -> Snapshot {
        let json = """
        {"policy":{"lifetime":"persistent","defaults":{"outbound":"allow"}},
        "rules":[{"id":"deny","direction":"outbound","family":"dual","action":"drop","terms":\(terms)}],
        "revision":{"generation":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
        """
        return try JSONDecoder().decode(Snapshot.self, from: Data(json.utf8))
    }
    func flow(_ address: String, _ port: UInt16 = 443) -> Flow {
        return Flow(direction: "outbound", ipv6: address.contains(":"), source: Address(address), destination: Address(address), sourcePort: 20000, destinationPort: port, proto: 6, application: nil)
    }
    func testPrefixNegationAndFamilies() throws {
        let policy = try snapshot("""
        [[{"match":{"field":"destination_prefix","prefix":"10.0.0.0/8"},"not":true}]]
        """)
        let program = try Program(policy)
        XCTAssertTrue(program.allows(flow("10.2.3.4")))
        XCTAssertFalse(program.allows(flow("192.0.2.1")))
        XCTAssertFalse(program.allows(flow("2001:db8::1")))
    }
    func testMissingIdentityCannotBecomePermission() throws {
        let policy = try snapshot("""
        [[{"match":{"field":"application","text":"com.example.app"},"not":true}]]
        """)
        let program = try Program(policy)
        XCTAssertFalse(program.allows(flow("192.0.2.1")))
    }
    func testPortRangeAndOR() throws {
        let policy = try snapshot("""
        [[{"match":{"field":"protocol","number":6}},{"match":{"field":"destination_port","ports":{"first":80,"last":90}}}],
         [{"match":{"field":"destination_prefix","prefix":"2001:db8::/32"}}]]
        """)
        let program = try Program(policy)
        XCTAssertFalse(program.allows(flow("192.0.2.1", 85)))
        XCTAssertTrue(program.allows(flow("192.0.2.1", 443)))
        XCTAssertFalse(program.allows(flow("2001:db8::1")))
    }
    func testUnsupportedAndMalformedFail() throws {
        XCTAssertThrowsError(try Program(snapshot("[[{\"match\":{\"field\":\"packet_mark\",\"number\":1}}]]")))
        XCTAssertThrowsError(try Prefix("invalid/24"))
        XCTAssertThrowsError(try Prefix("::/129"))
        let encoded = try JSONEncoder().encode(snapshot("[[]]"))
        XCTAssertNoThrow(try Program(JSONDecoder().decode(Snapshot.self, from: encoded)))
    }
}
