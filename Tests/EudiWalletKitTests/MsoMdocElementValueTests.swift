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
import MdocDataModel18013
import MdocDataTransfer18013
import SwiftCBOR
import Testing
@testable import EudiWalletKit

/// A requested mdoc element shows the value of the issued element, not a redacted description.
@Suite("mdoc element value")
struct MsoMdocElementValueTests {
	@Test("The string value of a requested element is the value of the issued element")
	func stringValueIsTheIssuedValue() throws {
		let issued = try IssuerSignedItem(cbor: .map([
			"digestID": .unsignedInt(1),
			"random": .byteString([1, 2, 3]),
			"elementIdentifier": .utf8String("family_name"),
			"elementValue": .utf8String("Doe"),
		]))
		let element = RequestItem(elementPath: ["family_name"])
			.extractMsoMdocElement(ns: "org.iso.18013.5.1", nsItems: [issued], docClaims: [], isMandatory: true)
		#expect(element.stringValue == "Doe")
		#expect(element.isValid)
	}
}
