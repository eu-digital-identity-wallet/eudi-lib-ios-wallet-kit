import CryptoKit
import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import OpenID4VP
import struct OpenID4VP.ClaimPath
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

    @Test("Array containers have empty display values and visible entries display their own values", arguments: [false, true])
    func nationalities(includeEntry: Bool) throws {
        let fixture = try makeFixture()
        var paths = [["nationalities"]]
        if includeEntry { paths.append(["nationalities", "0"]) }
        let element = try extract(fixture, paths: paths)
        let claim = try #require(element.docClaim)
        #expect(element.stringValue == "")
        #expect(claim.displayString.isEmpty)
        #expect(claim.children?.map(\.displayString) == (includeEntry ? ["LU"] : []))
        #expect(element.nestedElements?.map(\.stringValue) == (includeEntry ? ["LU"] : nil))
        let presented = try #require(try fixture.token.present(query: Set(paths.map { RequestItem(elementPath: $0).claimPath })))
        let recreated = try presented.recreateClaims().recreatedClaims
        let resolved = SdJwtUtils.resolveNestedSdClaims(recreated, disclosures: presented.disclosures, hashingAlg: "sha-256")
        #expect(resolved["nationalities"].arrayValue.map(\.stringValue) == (includeEntry ? ["LU"] : []))
    }

    @Test("A trailing null shows the array values in one selectable row")
    func terminalArrayWildcard() throws {
        let fixture = try makeFixture()
        let path = try JSONDecoder().decode(ClaimPath.self, from: Data(#"["mixed",null]"#.utf8))
        let request = ClaimsQuery(id: nil, path: path, values: nil, intentToRetain: nil)
        let item = try #require(OpenId4VpUtils.parseClaim(request, .sdjwt)?.1)
        let elements = try #require(fixture.token.extractSdJwtElements(
            docId: "pid", vct: "pid", displayName: nil, docClaims: fixture.claims, itemsRequested: ["": [item]]
        ))

        #expect(elements.sdJwtElements.count == 1)
        let element = try #require(elements.sdJwtElements.first)
        let claim = try #require(element.docClaim)
        #expect(element.stringValue == "private,visible")
        #expect(claim.displayString == "private,visible")
        #expect(claim.children == nil)
        #expect(element.nestedElements == nil)
        #expect(claim.path == ["mixed", ""])
        #expect(elements.selectedItemsDictionary[""]?.map(\.claimPath) == [item.claimPath])
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

    @Test("Over-asking uses the children revealed by an SD-JWT container request")
    func containerPolicy() throws {
        let fixture = try makeFixture()
        try expectPolicy(fixture, requested: [["place_of_birth"]], allowed: [["place_of_birth", "locality"]], warning: false)
        try expectPolicy(fixture, requested: [["place_of_birth"]], allowed: [["nationalities"]], warning: true)
        try expectPolicy(fixture, requested: [["place_of_birth"], ["place_of_birth", "region"]],
                         allowed: [["place_of_birth", "locality"]], warning: true)
        try expectPolicy(fixture, requested: [["profile"]], allowed: [["profile", "details", "hidden"]], warning: true)
        try expectPolicy(fixture, requested: [["profile"]], allowed: [["profile", "details", "visible"]], warning: false)
        try expectPolicy(fixture, requested: [["nationalities"]], allowed: [["nationalities", 0]], warning: false)
        try expectPolicy(fixture, requested: [["mixed"]], allowed: [["mixed", 0]], warning: true)
        try expectPolicy(fixture, requested: [["mixed"]], allowed: [["mixed", 1]], warning: false)
    }

    private func expectPolicy(_ fixture: Fixture, requested: [[String]], allowed: [[Any]], warning: Bool,
                              sourceLocation: SourceLocation = #_sourceLocation) throws {
        let policyPaths = try allowed.map { path in
            try JSONDecoder().decode(MdocDataModel18013.ClaimPath.self, from: JSONSerialization.data(withJSONObject: path))
        }
        let policy = WrpRegistrationPolicy(
            entitlements: [], sub: "test", country: "EU", policyID: [],
            credentials: [PolicyCredential(
                format: "dc+sd-jwt", meta: PolicyCredentialMeta(vctValues: ["pid"], doctypeValue: nil),
                claim: policyPaths.map { PolicyClaim(path: $0) })],
            purpose: [], registryURI: "https://example.test", certificatePolicy: "test",
            srvDescriptions: [], supportURI: "https://example.test",
            supervisoryAuthority: SupervisoryAuthority(email: "test@example.test", phone: "123", uri: "https://example.test"),
            privacyPolicy: "https://example.test", name: "Test", infoURI: "https://example.test",
            subLn: "test", iat: 0, status: nil
        )
        let claims = requested.map { path in
            ClaimsQuery(id: nil, path: ClaimPath(path.map { .claim(name: $0) }), values: nil, intentToRetain: nil)
        }
        let selection = try CredentialSelection(credentialId: "pid", docType: "pid", queryId: QueryId(value: "q"),
                                                optionId: "q-0", claimQueries: claims)
        var warnings = [String: [PresentationPolicyViolation]]()
        OpenId4VpUtils.validateDcqlPolicy(credentialSetOptions: ["q-0": [selection]], policy: policy,
                                          sdJwtDocuments: ["pid": fixture.token.serialisation], wrpVpWarnings: &warnings)
        #expect(!warnings.isEmpty == warning, sourceLocation: sourceLocation)
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
        let mixedEntry = try disclose(["mixed-entry-salt", "private"])
        let mixedValues: [Any] = [["...": mixedEntry], "visible"]
        let mixed = try disclose(["mixed-salt", "mixed", mixedValues])
        let hidden = try disclose(["hidden-salt", "hidden", "secret"])
        let profile = try disclose(["profile-salt", "profile", ["details": ["visible": "included", "_sd": [hidden]]]])
        let payload = try JSONSerialization.data(withJSONObject: ["_sd_alg": "sha-256", "_sd": [birthplace, nationalities, profile, mixed]]).base64URLEncodedString()
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
