import Foundation
import MdocDataModel18013
import OpenID4VP
import struct OpenID4VP.ClaimPath
import Testing
@testable import EudiWalletKit

struct OptionalCredentialSetsTests {
    private func query(includeSecondSet: Bool = true, firstRequired: Bool = false) throws -> DCQL {
        let secondSet = includeSecondSet ? #",{"options":[["rewards"]],"required":false}"# : ""
        return try JSONDecoder().decode(DCQL.self, from: Data("""
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["pid"]},"claims":[{"path":["name"]}]},
          {"id":"rewards","format":"dc+sd-jwt","meta":{"vct_values":["rewards"]},"claims":[{"path":["name"]}]}
        ],"credential_sets":[{"options":[["pid"]],"required":\(firstRequired)}\(secondSet)]}
        """.utf8))
    }

    private func wallet(_ types: [String]) -> DefaultDcqlQueryable {
        DefaultDcqlQueryable(
            credentials: Dictionary(uniqueKeysWithValues: types.map { ($0, ($0, DocDataFormat.sdjwt)) }),
            claimPaths: Dictionary(uniqueKeysWithValues: types.map {
                ($0, [ClaimPath([.claim(name: "name")])])
            })
        )
    }

    @Test func singleOptionalSetOffersMatchingCredential() throws {
        let result = try OpenId4VpUtils.resolveDcql(query(includeSecondSet: false), queryable: wallet(["pid"]))
        #expect(Array(result.keys) == ["pid-0"])
        #expect(result.values.first?.map(\.credentialId) == ["pid"])
        #expect(result.values.first?.first?.claimQueries.count == 1)
    }

    @Test func optionalSetsOfferEveryNonemptyCombination() throws {
        let result = try OpenId4VpUtils.resolveDcql(query(), queryable: wallet(["pid", "rewards"]))
        #expect(Set(result.keys) == ["pid-0", "rewards-0", "pid-0|rewards-0"])
        #expect(result["pid-0"]?.map(\.credentialId) == ["pid"])
        #expect(result["rewards-0"]?.map(\.credentialId) == ["rewards"])
        #expect(result["pid-0|rewards-0"]?.map(\.credentialId) == ["pid", "rewards"])
    }

    @Test func unavailableOptionalSetCanBeSkipped() throws {
        let result = try OpenId4VpUtils.resolveDcql(query(), queryable: wallet(["rewards"]))
        #expect(Array(result.keys) == ["rewards-0"])
        #expect(result.values.first?.map(\.credentialId) == ["rewards"])
    }

    @Test func noMatchingOptionalCredentialsStillFails() throws {
        #expect(throws: WalletError.self) {
            try OpenId4VpUtils.resolveDcql(query(), queryable: wallet([]))
        }
    }

    @Test func missingRequiredSetCannotBeSkipped() throws {
        #expect(throws: WalletError.self) {
            try OpenId4VpUtils.resolveDcql(query(firstRequired: true), queryable: wallet(["rewards"]))
        }
    }
}
