import XCTest
@testable import EudiWalletKit
import PresentationExchange

final class EudiWalletKitTests: XCTestCase {
    func testExample() throws {
        // XCTest Documentation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
    }
	
	func testParsePresentationDefinition() throws {
		let testPD = try JSONDecoder().decode(PresentationDefinition.self, from: Data(name: "TestPresentationDefinition", ext: "json", from: Bundle.module)! )
		let items = try XCTUnwrap(OpenId4VpService.parsePresentationDefinition(testPD))
		XCTAssert(!items.keys.isEmpty)
		print(items)
	}
}
