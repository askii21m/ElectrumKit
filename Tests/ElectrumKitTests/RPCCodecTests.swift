import XCTest
@testable import ElectrumKit

/// JSON-RPC 2.0 framing: request encoding, response/notification/error decoding. The
/// notification cases pin the behaviour the Frigate-compatibility fix depends on.
final class RPCCodecTests: XCTestCase {

    func testRequestEncodesJSONRPC2() throws {
        let request = RPCRequest(method: "blockchain.scripthash.listunspent", params: ["abcd"], id: 7)
        let json = try JSONSerialization.jsonObject(with: try JSONEncoder().encode(request)) as! [String: Any]
        XCTAssertEqual(json["jsonrpc"] as? String, "2.0")
        XCTAssertEqual(json["method"] as? String, "blockchain.scripthash.listunspent")
        XCTAssertEqual(json["id"] as? Int, 7)
        XCTAssertEqual((json["params"] as? [Any])?.first as? String, "abcd")
    }

    func testResponseDecodesResultAndId() throws {
        let json = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":\"deadbeef\"}"
        let response = try JSONDecoder().decode(RPCResponse.self, from: Data(json.utf8))
        XCTAssertEqual(response.id, 3)
        XCTAssertEqual(response.result?.value as? String, "deadbeef")
        XCTAssertNil(response.error)
    }

    func testResponseDecodesError() throws {
        let json = "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-32601,\"message\":\"unknown method\"}}"
        let response = try JSONDecoder().decode(RPCResponse.self, from: Data(json.utf8))
        XCTAssertEqual(response.error?.code, -32601)
        XCTAssertEqual(response.error?.message, "unknown method")
    }

    // A standard Electrum scripthash notification: positional params [scripthash, status].
    func testPositionalNotificationDecodesToArray() throws {
        let json = "{\"jsonrpc\":\"2.0\",\"method\":\"blockchain.scripthash.subscribe\",\"params\":[\"abcd\",\"status1\"]}"
        let notification = try JSONDecoder().decode(RPCNotification.self, from: Data(json.utf8))
        XCTAssertEqual(notification.method, "blockchain.scripthash.subscribe")
        let params = try XCTUnwrap(notification.params.value as? [Any])
        XCTAssertEqual(params.count, 2)
        XCTAssertEqual(params[1] as? String, "status1")
    }

    // The Frigate silent-payments notification: BY-NAME object params. Before the fix,
    // handleNotification cast params to [Any], failed, and dropped this entirely. The
    // decoded value must be a [String: Any] so the method-routed handler can consume it.
    func testFrigateObjectNotificationDecodesToObject() throws {
        let json = """
        {"jsonrpc":"2.0","method":"blockchain.silentpayments.subscribe","params":{\
        "subscription":{"address":"sp1qtest","labels":[0],"start_height":882000},\
        "progress":1.0,\
        "history":[{"height":890004,"tx_hash":"acc3758b","tweak_key":"0314bec1"},\
        {"height":0,"tx_hash":"f4184fc5","tweak_key":"03aeea54"}]}}
        """
        let notification = try JSONDecoder().decode(RPCNotification.self, from: Data(json.utf8))
        XCTAssertEqual(notification.method, "blockchain.silentpayments.subscribe")

        let params = try XCTUnwrap(notification.params.value as? [String: Any])
        // Foundation coerces a JSON `1.0` to Int; read progress via NSNumber so a
        // consumer handles both integral (1.0 -> 1) and fractional (0.5) progress.
        XCTAssertEqual((params["progress"] as? NSNumber)?.doubleValue, 1.0)
        XCTAssertEqual((params["subscription"] as? [String: Any])?["start_height"] as? Int, 882000)

        let history = try XCTUnwrap(params["history"] as? [Any])
        XCTAssertEqual(history.count, 2)
        let first = try XCTUnwrap(history[0] as? [String: Any])
        XCTAssertEqual(first["height"] as? Int, 890004)
        XCTAssertEqual(first["tweak_key"] as? String, "0314bec1")
        XCTAssertEqual((history[1] as? [String: Any])?["height"] as? Int, 0) // mempool
    }

    // KEEPALIVE LIVENESS: any received message proves the connection is alive. Without the
    // reset, a sustained pipelined burst (a wallet's initial history scan) starved the ping
    // past its 10s timeout twice in a row and `bounce()` killed a healthy, merely-busy
    // connection mid-scan -- failing every in-flight request and turning a ~3s scan into ~50s
    // of timeout-retry waves (observed live against Fulcrum 2.1.0).
    func testReceivedNotificationResetsKeepaliveFailures() {
        let client = ElectrumClient(host: "example.invalid", port: 50002)
        client.pingFailures = 1   // one strike: the next failure would bounce

        let received = XCTestExpectation(description: "notification delivered")
        client.subscribe(toMethod: "blockchain.scripthash.subscribe") { _ in received.fulfill() }
        let json = "{\"jsonrpc\":\"2.0\",\"method\":\"blockchain.scripthash.subscribe\",\"params\":[\"abcd\",\"s1\"]}"
        client.processMessage(Data(json.utf8))
        wait(for: [received], timeout: 2.0)

        XCTAssertEqual(client.pingFailures, 0, "a live notification must clear keepalive strikes")
    }

    func testReceivedResponseResetsKeepaliveFailures() {
        let client = ElectrumClient(host: "example.invalid", port: 50002)
        client.pingFailures = 1

        // Even a response to an id we no longer track proves the socket is alive.
        client.processMessage(Data("{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":\"ok\"}".utf8))
        let drained = XCTestExpectation(description: "network queue drained")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { drained.fulfill() }
        wait(for: [drained], timeout: 2.0)

        XCTAssertEqual(client.pingFailures, 0, "a live response must clear keepalive strikes")
    }

    // Frigate attaches a NON-STANDARD `id` to its silent-payments notifications. Keying
    // off id-presence (the original bug) mis-routes them into the request/response path,
    // where they are dropped as a response to an unknown id. processMessage must route by
    // `method` first, so the method-routed handler still receives them.
    func testIdBearingNotificationRoutesToMethodHandlerNotResponse() {
        let client = ElectrumClient(host: "example.invalid", port: 50002)
        let received = XCTestExpectation(description: "method handler receives the id-bearing notification")
        var deliveredHistory: Int?
        client.subscribe(toMethod: "blockchain.silentpayments.subscribe") { raw in
            deliveredHistory = ((raw as? [String: Any])?["history"] as? [Any])?.count
            received.fulfill()
        }
        // The exact live Frigate shape: a by-name object params AND a trailing `id`.
        let json = """
        {"jsonrpc":"2.0","method":"blockchain.silentpayments.subscribe","params":{\
        "subscription":{"address":"sp1qtest","labels":[0],"start_height":0},"progress":1.0,\
        "history":[{"height":0,"tx_hash":"9cdd","tweak_key":"03605de1"}]},"id":2}
        """
        client.processMessage(Data(json.utf8))
        wait(for: [received], timeout: 2.0)
        XCTAssertEqual(deliveredHistory, 1)
    }
}
