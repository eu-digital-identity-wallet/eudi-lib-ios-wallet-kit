/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Testing
@testable import EudiWalletKit
import Foundation
import MdocDataModel18013
import WalletStorage
import SwiftCBOR
import OpenID4VCI
import struct OpenID4VCI.ClaimPath
import enum OpenID4VCI.ClaimPathElement

struct MandatoryClaimsTests {

	private func document(_ resource: String, format: DocDataFormat) throws -> WalletStorage.Document {
		var data = try #require(Data(name: resource, ext: "txt", from: Bundle.module))
		if format == .cbor {
			let base64Url = try #require(String(data: data, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
			data = try #require(Data(base64URLEncoded: base64Url))
		}
		return WalletStorage.Document(id: UUID().uuidString, docType: "", docDataFormat: format, data: data,
			docKeyInfo: nil, createdAt: .now, metadata: nil, displayName: nil, status: .issued)
	}

	private func path(_ components: ClaimPathElement...) -> ClaimPath { ClaimPath(components) }
	private func key(_ name: String) -> ClaimPathElement { .claim(name: name) }

	private func missing(_ doc: WalletStorage.Document, _ paths: ClaimPath...) -> [ClaimPath] {
		OpenId4VciService.missingMandatoryClaims(doc, mandatoryClaims: paths)
	}

	@Test func rejectionIsOffByDefault() {
		#expect(OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example").rejectMissingMandatoryClaims == false)
		#expect(OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example", rejectMissingMandatoryClaims: true).rejectMissingMandatoryClaims)
	}

	@Test func sdJwtWithAllMandatoryClaimsPasses() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		#expect(missing(doc, path(key("family_name")), path(key("given_name")), path(key("birthdate"))).isEmpty)
	}

	@Test func sdJwtMissingMandatoryClaimFails() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		#expect(missing(doc, path(key("family_name")), path(key("not_issued"))) == [path(key("not_issued"))])
	}

	@Test func sdJwtNestedMandatoryClaimPasses() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		#expect(missing(doc, path(key("address"), key("postal_code"))).isEmpty)
	}

	@Test func sdJwtMissingNestedMandatoryClaimFails() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		#expect(missing(doc, path(key("address"), key("not_issued"))) == [path(key("address"), key("not_issued"))])
	}

	@Test func sdJwtArraySelectorsSelectTheElements() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		#expect(missing(doc, path(key("nationalities"), .arrayElement(index: 0)), path(key("nationalities"), .allArrayElements)).isEmpty)
	}

	@Test func sdJwtArraySelectorsFailOnAMissingIndexOrAWrongType() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		let outOfBounds = path(key("nationalities"), .arrayElement(index: 5))
		let notAnArray = path(key("family_name"), .allArrayElements)
		#expect(missing(doc, outOfBounds, notAnArray) == [outOfBounds, notAnArray])
	}

	@Test func mdocWithAllMandatoryClaimsPasses() throws {
		let doc = try document("mdoc-mdl", format: .cbor)
		#expect(missing(doc, path(key("org.iso.18013.5.1"), key("family_name")), path(key("org.iso.18013.5.1"), key("given_name"))).isEmpty)
	}

	@Test func mdocMissingMandatoryClaimFails() throws {
		let doc = try document("mdoc-mdl", format: .cbor)
		let notIssued = path(key("org.iso.18013.5.1"), key("not_issued"))
		let otherNameSpace = path(key("other.namespace"), key("family_name"))
		#expect(missing(doc, notIssued, otherNameSpace) == [notIssued, otherNameSpace])
	}

	@Test func mdocPathIntoADataElementSelectsTheNestedClaim() throws {
		let doc = try document("mdoc-mdl", format: .cbor)
		let category = path(key("org.iso.18013.5.1"), key("driving_privileges"), .allArrayElements, key("vehicle_category_code"))
		let first = path(key("org.iso.18013.5.1"), key("driving_privileges"), .arrayElement(index: 0))
		let notIssued = path(key("org.iso.18013.5.1"), key("driving_privileges"), .allArrayElements, key("not_issued"))
		#expect(missing(doc, category, first, notIssued) == [notIssued])
	}

	@Test func mdocWithoutNameSpacesFailsAllMandatoryClaims() throws {
		let doc = try document("mdoc-mdl", format: .cbor)
		let issuerSigned = try IssuerSigned(data: [UInt8](doc.data))
		let withoutNameSpaces = IssuerSigned(issuerNameSpaces: nil, issuerAuth: issuerSigned.issuerAuth)
		let stripped = WalletStorage.Document(id: doc.id, docType: "", docDataFormat: .cbor,
			data: Data(withoutNameSpaces.encode(options: CBOROptions())), docKeyInfo: nil, createdAt: .now,
			metadata: nil, displayName: nil, status: .issued)
		let familyName = path(key("org.iso.18013.5.1"), key("family_name"))
		#expect(missing(stripped, familyName) == [familyName])
	}

	@Test func notificationDescriptionRemovesCharactersOutsideTheAllowedSet() {
		#expect(OpenId4VciService.notificationDescription("missing: \"näme\\x\"") == "missing: nmex")
		#expect(OpenId4VciService.notificationDescription("missing mandatory claims: family_name") == "missing mandatory claims: family_name")
		#expect(OpenId4VciService.notificationDescription(nil) == nil)
	}
}
