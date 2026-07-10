import XCTest
import Network
@testable import ElectrumKit

/// The same-status migration decision (NWPath itself is not constructible in tests, so the
/// decision is a static function over the path's projected fields).
final class PathMigrationTests: XCTestCase {

    func testWifiToCellularHandoverIsMigration() {
        // Preferred en0 gone, pdp_ip0 carries the still-satisfied path: the socket is stranded.
        XCTAssertTrue(ElectrumClient.isPathMigration(
            status: .satisfied,
            lastStatus: .satisfied,
            availableInterfaceNames: ["pdp_ip0"],
            lastPrimaryInterfaceName: "en0"
        ))
    }

    func testInterfaceAdditionIsNotMigration() {
        // Wifi joins over a live cellular socket: old interface still available, no bounce.
        XCTAssertFalse(ElectrumClient.isPathMigration(
            status: .satisfied,
            lastStatus: .satisfied,
            availableInterfaceNames: ["en0", "pdp_ip0"],
            lastPrimaryInterfaceName: "pdp_ip0"
        ))
    }

    func testStatusTransitionsAreNotMigrations() {
        // Status changes take the existing unsatisfied/satisfied branches, never the bounce.
        XCTAssertFalse(ElectrumClient.isPathMigration(
            status: .unsatisfied,
            lastStatus: .satisfied,
            availableInterfaceNames: [],
            lastPrimaryInterfaceName: "en0"
        ))
        XCTAssertFalse(ElectrumClient.isPathMigration(
            status: .satisfied,
            lastStatus: .unsatisfied,
            availableInterfaceNames: ["pdp_ip0"],
            lastPrimaryInterfaceName: "en0"
        ))
    }

    func testFirstUpdateIsNotMigration() {
        XCTAssertFalse(ElectrumClient.isPathMigration(
            status: .satisfied,
            lastStatus: nil,
            availableInterfaceNames: ["en0"],
            lastPrimaryInterfaceName: nil
        ))
    }

    func testUnchangedPreferredInterfaceIsNotMigration() {
        XCTAssertFalse(ElectrumClient.isPathMigration(
            status: .satisfied,
            lastStatus: .satisfied,
            availableInterfaceNames: ["en0", "pdp_ip0"],
            lastPrimaryInterfaceName: "en0"
        ))
    }
}
