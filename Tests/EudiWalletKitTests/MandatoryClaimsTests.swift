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

	private func claim(_ path: [String], mandatory: Bool? = true) -> DocClaimMetadata {
		DocClaimMetadata(display: nil, isMandatory: mandatory, claimPath: path, valueType: nil)
	}

	@Test func sdJwtWithAllMandatoryClaimsPasses() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		let claims = [claim(["family_name"]), claim(["given_name"]), claim(["birthdate"])]
		#expect(OpenId4VciService.missingMandatoryClaims(doc, claims: claims).isEmpty)
	}

	@Test func sdJwtMissingMandatoryClaimFails() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		let claims = [claim(["family_name"]), claim(["not_issued"]), claim(["also_not_issued"], mandatory: false)]
		#expect(OpenId4VciService.missingMandatoryClaims(doc, claims: claims) == ["not_issued"])
	}

	@Test func sdJwtIgnoresNestedPaths() throws {
		let doc = try document("sjwt-pid-python", format: .sdjwt)
		#expect(OpenId4VciService.missingMandatoryClaims(doc, claims: [claim(["address", "not_issued"])]).isEmpty)
	}

	@Test func mdocWithAllMandatoryClaimsPasses() throws {
		let doc = try document("mdoc-mdl", format: .cbor)
		let claims = [claim(["org.iso.18013.5.1", "family_name"]), claim(["org.iso.18013.5.1", "given_name"])]
		#expect(OpenId4VciService.missingMandatoryClaims(doc, claims: claims).isEmpty)
	}

	@Test func mdocMissingMandatoryClaimFails() throws {
		let doc = try document("mdoc-mdl", format: .cbor)
		let claims = [claim(["org.iso.18013.5.1", "not_issued"]), claim(["other.namespace", "family_name"])]
		#expect(OpenId4VciService.missingMandatoryClaims(doc, claims: claims)
			== ["org.iso.18013.5.1.not_issued", "other.namespace.family_name"])
	}
}
