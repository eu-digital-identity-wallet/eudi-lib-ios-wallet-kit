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

import Foundation
import Testing
import MdocDataModel18013
import eudi_lib_sdjwt_swift
@testable import EudiWalletKit

/// OpenID4VP 1.0 section 6.4.1: a credential query without claims requests no selectively disclosable claims.
@Suite("Credential request without claims")
struct NoClaimsRequestTests {
	@Test("An mdoc request without items selects no elements")
	func mdocRequestWithoutItems() throws {
		let fixture = try #require(Data(name: "mdoc-mdl", ext: "txt", from: Bundle.module))
		let text = try #require(String(data: fixture, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
		let issuerSigned = try IssuerSigned(data: [UInt8](try #require(Data(base64urlEncoded: text))))
		let claim = DocClaim(name: "family_name", path: ["org.iso.18013.5.1", "family_name"], dataValue: .string("Doe"), stringValue: "Doe")
		let elements = issuerSigned.extractMsoMdocElements(docId: "doc", docType: issuerSigned.issuerAuth.mso.docType, displayName: nil, docClaims: [claim], itemsRequested: [:])
		#expect(elements.nameSpacedElements.isEmpty)
		#expect(DocElements.msoMdoc(elements).selectedItemsDictionary.isEmpty)
	}

	@Test("An SD-JWT request without items selects no claims")
	func sdJwtRequestWithoutItems() throws {
		let data = try #require(Data(name: "sjwt-pid-python", ext: "txt", from: Bundle.module))
		let sdJwt = try CompactParser().getSignedSdJwt(serialisedString: try #require(String(data: data, encoding: .utf8)))
		let elements = try #require(sdJwt.extractSdJwtElements(docId: "doc", vct: "urn:eudi:pid:1", displayName: nil, docClaims: [], itemsRequested: [:]))
		#expect(elements.sdJwtElements.isEmpty)
		#expect(DocElements.sdJwt(elements).selectedItemsDictionary[""]?.isEmpty == true)
	}
}
