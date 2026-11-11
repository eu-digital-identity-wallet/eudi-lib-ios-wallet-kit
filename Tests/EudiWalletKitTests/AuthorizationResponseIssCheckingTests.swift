import MdocDataModel18013
import OpenID4VCI
import Testing
@testable import EudiWalletKit

@Suite("Authorization response iss checking")
struct AuthorizationResponseIssCheckingTests {
    @Test("Uses .never by default")
    func defaultPolicyIsNever() async throws {
        let config = try await OpenId4VciConfiguration(credentialIssuerURL: nil, clientId: "wallet")
            .toOpenId4VCIConfig(credentialIssuerId: "https://issuer.example.com", clientAttestationPopSigningAlgValuesSupported: nil, context: ThreadSafeAuthContext())
        #expect(config.authResponseIssChecking == .never)
    }

    @Test("Gives the iss policy to the OpenID4VCI configuration", arguments: [AuthorizationResponseIssChecking.never, .ifSupported, .required])
    func passesPolicy(_ policy: AuthorizationResponseIssChecking) async throws {
        let config = try await OpenId4VciConfiguration(credentialIssuerURL: nil, clientId: "wallet", authResponseIssChecking: policy)
            .toOpenId4VCIConfig(credentialIssuerId: "https://issuer.example.com", clientAttestationPopSigningAlgValuesSupported: nil, context: ThreadSafeAuthContext())
        #expect(config.authResponseIssChecking == policy)
    }
}
