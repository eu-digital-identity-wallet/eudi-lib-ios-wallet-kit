import Foundation
import Testing
@testable import EudiWalletKit

struct WrpRegistrationPolicyTests {
    @Test("Decode base64url registration certificate and print srv_description")
    func decodeRegistrationCertificate() throws {
        let url = try #require(Bundle.module.url(forResource: "test_reg_cert", withExtension: "txt"))
        let encoded = try String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let data = try #require(Data(base64urlEncoded: encoded))
        let policy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: data)
        let descriptions = try #require(policy.srvDescription)

        #expect(descriptions == [PolicyPurpose(lang: "en", value: "Verifier DEV")])
        for description in descriptions {
            print("srv_description [\(description.lang)]: \(description.value)")
        }
    }
}
