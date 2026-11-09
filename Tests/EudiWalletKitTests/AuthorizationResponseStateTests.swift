import Testing
@testable import EudiWalletKit

@Suite("Authorization response state")
struct AuthorizationResponseStateTests {
    @Test("Returns the state of the authorization response")
    func returnsState() throws {
        #expect(try OpenId4VciService.authorizationResponseState("abc") == "abc")
    }

    @Test("Rejects an authorization response without a state")
    func rejectsMissingState() {
        #expect(throws: WalletError.self) {
            try OpenId4VciService.authorizationResponseState(nil)
        }
    }
}
