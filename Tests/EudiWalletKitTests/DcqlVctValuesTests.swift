/*
 Copyright (c) 2026 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Foundation
import Testing
import OpenID4VP
@testable import EudiWalletKit

struct DcqlVctValuesTests {
    private func query(multiple: Bool = false) throws -> DCQL {
        let json = """
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","multiple":\(multiple),
        "meta":{"vct_values":["urn:eudi:pid:1","urn:eu.europa.ec.eudi:pid:1","urn:eu.europa.ec.eudi:pid:1"]},
        "claims":[{"path":["family_name"]}]}]}
        """
        return try JSONDecoder().decode(DCQL.self, from: Data(json.utf8))
    }

    @Test func laterTypeSurvivesFormatFilteringAndResolution() throws {
        let dcql = try query()
        let heldType = "urn:eu.europa.ec.eudi:pid:1"
        let types = ["held": heldType, "unrelated": "other"]
        let (formats, descriptors, _) = try OpenId4VpUtils.parseDcqlFormats(dcql, idsToDocTypes: types)
        #expect(formats.count == 2)
        #expect(formats[heldType] == .sdjwt)
        #expect(descriptors[heldType] == "pid")
        let credentials = OpenId4VpUtils.makeCredentialMap(idsToDocTypes: types, formatsRequested: formats)
        #expect(credentials.count == 1)
        let queryable = DefaultDcqlQueryable(credentials: credentials, claimPaths: ["held": [.claim("family_name")]])
        let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: queryable)
        let selection = try #require(result.values.first?.first)
        #expect(result.count == 1)
        #expect(selection.credentialId == "held")
        #expect(selection.docType == heldType)
        #expect(selection.queryId.value == "pid")
    }

    @Test(arguments: [false, true]) func matchesAllTypesWithoutDuplicates(multiple: Bool) throws {
        let dcql = try query(multiple: multiple)
        let queryable = DefaultDcqlQueryable(credentials: [
            "first": ("urn:eudi:pid:1", .sdjwt),
            "second": ("urn:eu.europa.ec.eudi:pid:1", .sdjwt),
            "wrongFormat": ("urn:eu.europa.ec.eudi:pid:1", .cbor),
            "unrelated": ("other", .sdjwt)
        ], claimPaths: Dictionary(uniqueKeysWithValues: ["first", "second", "wrongFormat", "unrelated"].map { ($0, [ClaimPath.claim("family_name")]) }))
        let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: queryable)
        let selections = result.values.flatMap { $0 }
        #expect(result.count == (multiple ? 1 : 2))
        #expect(selections.count == 2)
        #expect(Set(selections.map(\.credentialId)) == ["first", "second"])
        #expect(Set(selections.map(\.docType)) == ["urn:eudi:pid:1", "urn:eu.europa.ec.eudi:pid:1"])
    }

    @Test func continuesAfterFirstTypeFailsClaimRequirements() throws {
        let dcql = try query()
        let queryable = DefaultDcqlQueryable(credentials: [
            "first": ("urn:eudi:pid:1", .sdjwt), "second": ("urn:eu.europa.ec.eudi:pid:1", .sdjwt)
        ], claimPaths: ["second": [.claim("family_name")]])
        let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: queryable)
        #expect(result.count == 1)
        #expect(result.values.first?.first?.credentialId == "second")
    }

    @Test func rejectsUnlistedType() throws {
        let dcql = try query()
        let queryable = DefaultDcqlQueryable(credentials: ["other": ("other", .sdjwt)], claimPaths: [:])
        #expect(throws: WalletError.self) { try OpenId4VpUtils.resolveDcql(dcql, queryable: queryable) }
    }

    @Test func laterTypeSatisfiesRequiredCredentialSet() throws {
        let data = try JSONEncoder().encode(query())
        var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        json["credential_sets"] = [["options": [["pid"]], "required": true]]
        let dcql = try JSONDecoder().decode(DCQL.self, from: JSONSerialization.data(withJSONObject: json))
        let queryable = DefaultDcqlQueryable(credentials: ["held": ("urn:eu.europa.ec.eudi:pid:1", .sdjwt)],
                                             claimPaths: ["held": [.claim("family_name")]])
        let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: queryable)
        #expect(result.values.first?.first?.credentialId == "held")
    }

    @Test func mdocStillMatchesItsSingleDocumentType() throws {
        let data = Data(#"{"credentials":[{"id":"mdoc","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}"#.utf8)
        let dcql = try JSONDecoder().decode(DCQL.self, from: data)
        let queryable = DefaultDcqlQueryable(credentials: ["mdl": ("org.iso.18013.5.1.mDL", .cbor)], claimPaths: [:])
        let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: queryable)
        #expect(result.values.first?.first?.credentialId == "mdl")
        #expect(result.values.first?.first?.docType == "org.iso.18013.5.1.mDL")
    }

}
