import CryptoKit
import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import SwiftyJSON
import Testing
import eudi_lib_sdjwt_swift
@testable import EudiWalletKit

@Suite("SD-JWT container disclosure display")
struct SdJwtContainerDisclosureTests {
    @Test("Container requests show only values carried by the selected disclosures", arguments: [false, true])
    func birthplace(includeLocality: Bool) throws {
        let fixture = try makeFixture()
        var paths = [["place_of_birth"]]
        if includeLocality { paths.append(["place_of_birth", "locality"]) }
        let element = try extract(fixture, paths: paths)
        #expect(element.docClaim?.children?.map(\.name) == (includeLocality ? ["locality"] : []))
        #expect(element.stringValue == (includeLocality ? "{locality: Luxembourg}" : "{}"))
        #expect(element.docClaim?.stringValue == element.stringValue)
        #expect(element.nestedElements?.map(\.elementPath) == (includeLocality ? [["place_of_birth", "locality"]] : nil))
        let presented = try #require(try fixture.token.present(query: Set(paths.map { RequestItem(elementPath: $0).claimPath })))
        let value = try presented.recreateClaims().recreatedClaims["place_of_birth"]
        #expect(value.dictionaryValue.keys.sorted() == (includeLocality ? ["locality"] : []))
        // Building presentation elements must not mutate the stored credential claims.
        #expect(fixture.claims.first { $0.name == "place_of_birth" }?.children?.count == 3)
    }

    @Test("Array container summaries omit undisclosed entries", arguments: [false, true])
    func nationalities(includeEntry: Bool) throws {
        let fixture = try makeFixture()
        var paths = [["nationalities"]]
        if includeEntry { paths.append(["nationalities", "0"]) }
        let element = try extract(fixture, paths: paths)
        #expect(element.docClaim?.children?.map(\.stringValue) == (includeEntry ? ["LU"] : []))
        #expect(element.stringValue == (includeEntry ? "LU" : "[]"))
        #expect(element.docClaim?.stringValue == element.stringValue)
        let presented = try #require(try fixture.token.present(query: Set(paths.map { RequestItem(elementPath: $0).claimPath })))
        let recreated = try presented.recreateClaims().recreatedClaims
        let resolved = SdJwtUtils.resolveNestedSdClaims(recreated, disclosures: presented.disclosures, hashingAlg: "sha-256")
        #expect(resolved["nationalities"].arrayValue.map(\.stringValue) == (includeEntry ? ["LU"] : []))
    }

    @Test("Inline children remain visible and nested summaries omit separate disclosures")
    func inlineChildren() throws {
        let fixture = try makeFixture()
        let element = try extract(fixture, paths: [["profile"]])
        let details = try #require(element.docClaim?.children?.first)
        #expect(details.name == "details")
        #expect(details.children?.map(\.name) == ["visible"])
        #expect(details.stringValue == "{visible: included}")
        #expect(element.stringValue == "{details: {visible: included}}")
        #expect(element.docClaim?.style == "profile-style")
    }

    private func extract(_ fixture: Fixture, paths: [[String]]) throws -> SdJwtElement {
        let elements = try #require(fixture.token.extractSdJwtElements(docId: "pid", vct: "pid", displayName: nil, docClaims: fixture.claims, itemsRequested: ["": paths.map { RequestItem(elementPath: $0) }]))
        return try #require(elements.sdJwtElements.first)
    }

    private struct Fixture {
        let token: SignedSDJWT
        let claims: [DocClaim]
    }

    private func makeFixture() throws -> Fixture {
        var disclosures: [String] = []
        func disclose(_ value: [Any]) throws -> String {
            let encoded = try JSONSerialization.data(withJSONObject: value).base64URLEncodedString()
            disclosures.append(encoded)
            return Data(SHA256.hash(data: Data(encoded.utf8))).base64URLEncodedString()
        }
        let country = try disclose(["country-salt", "country", "LU"])
        let locality = try disclose(["locality-salt", "locality", "Luxembourg"])
        let region = try disclose(["region-salt", "region", "Luxembourg"])
        let birthplace = try disclose(["birthplace-salt", "place_of_birth", ["_sd": [country, locality, region]]])
        let nationality = try disclose(["nationality-salt", "LU"])
        let nationalities = try disclose(["nationalities-salt", "nationalities", [["...": nationality]]])
        let hidden = try disclose(["hidden-salt", "hidden", "secret"])
        let profile = try disclose(["profile-salt", "profile", ["details": ["visible": "included", "_sd": [hidden]]]])
        let payload = try JSONSerialization.data(withJSONObject: ["_sd_alg": "sha-256", "_sd": [birthplace, nationalities, profile]]).base64URLEncodedString()
        let header = Data(#"{"alg":"ES256"}"#.utf8).base64URLEncodedString()
        let signature = Data(repeating: 0, count: 64).base64URLEncodedString()
        let compact = "\(header).\(payload).\(signature)~\(disclosures.joined(separator: "~"))~"
        let token = try CompactParser().getSignedSdJwt(serialisedString: compact)
        let json = try #require(SdJwtUtils.recreateSdJwtClaims(docData: Data(compact.utf8))?.json)
        var claims = try #require(json.toClaimsArray(pathPrefix: [], nil, nil)?.0)
        if let index = claims.firstIndex(where: { $0.name == "profile" }) { claims[index].style = "profile-style" }
        return Fixture(token: token, claims: claims)
    }
}
