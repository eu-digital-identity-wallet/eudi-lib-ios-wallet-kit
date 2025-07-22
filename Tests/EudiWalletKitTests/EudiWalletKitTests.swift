/*
 * Copyright (c) 2023 European Commission
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
import CryptoKit
import PresentationExchange
import MdocDataModel18013
import WalletStorage
import SwiftCBOR
@testable import JOSESwift
import eudi_lib_sdjwt_swift

struct EudiWalletKitTests {

	@Test("Parse Presentation Definition", arguments: [DocDataFormat.cbor, .sdjwt])
	func testParsePresentationDefinition(format: DocDataFormat) throws {
		let testPDData = Data(name: "presDef-\(format.rawValue)", ext: "json", from: Bundle.module)!
		let testPD = try JSONDecoder().decode(PresentationDefinition.self, from: testPDData)
		let (items, fmtsRequested, _) = try Openid4VpUtils.parsePresentationDefinition(testPD,  idsToDocTypes: [:], dataFormats: [:], docDisplayNames: [:])
		let items1 = try #require(items)
		let docType = try #require(items1.first?.key)
		let nsItems = try #require(items1.first?.value.first)
		#expect(!nsItems.value.isEmpty && nsItems.value.count > 1)
		print("DocType: ", docType, "ns:", nsItems.key, "Items: ", nsItems.value.map(\.elementIdentifier))
		#expect(fmtsRequested.allSatisfy({ (k,v) in v == format }))
	}

	@Test("Get VCT from sd-jwt", arguments: ["mdl", "pid"])
	func testParseJwt(dt: String) async throws {
		let dataFileName = "sjwt-\(dt)"
		let data = Data(name: dataFileName, ext: "txt", from: Bundle.module)!
		let parser = CompactParser()
		let sdJwt = try parser.getSignedSdJwt(serialisedString: String(data: data, encoding: .utf8)!)
		let paths = try sdJwt.recreateClaims()
		if dt == "pid" {
			let family_name = try #require(paths.recreatedClaims["family_name"].string)
			let given_name = try #require(paths.recreatedClaims["given_name"].string)
			print(family_name, given_name)
		}
	}

	@Test("Get docType from mdoc", arguments: ["mdl"])
	func testParseMdoc(dt: String) throws {
		let data = Data(name: "mdoc-\(dt)", ext: "txt", from: Bundle.module)!
		let strData = try #require(String(data: data, encoding: .utf8))
		let base64Data = try #require(Data(base64URLEncoded: strData))
		let dr = try #require(DeviceResponse(data: [UInt8](base64Data)))
		let iss = try #require(dr.documents?.first?.issuerSigned)
		#expect("org.iso.18013.5.1.mDL" == iss.issuerAuth.mso.docType)
	}

	let ANNEX_B_OPENID4VP_HANDOVER = "835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930"
	let ANNEX_B_SESSION_TRANSCRIPT = "83F6F6835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930"

	let clientId = "example.com"
	let responseUri = "https://example.com/12345/response"
	let nonce = "abcdefgh1234567890"
	let mdocGeneratedNonce = "1234567890abcdefgh"

	@Test func testGenerateOpenId4VpHandover() {
		let openid4VpHandover = Openid4VpUtils.generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri, nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce)
		#expect(ANNEX_B_OPENID4VP_HANDOVER == openid4VpHandover.encode().toHexString().uppercased())
	}

	@Test func testGenerateSessionTranscript() {
		let sessionTranscript = Openid4VpUtils.generateSessionTranscript(clientId: clientId, responseUri: responseUri, nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce).encode(options: CBOROptions())
		#expect(ANNEX_B_SESSION_TRANSCRIPT == sessionTranscript.toHexString().uppercased())
	}

	@Test func testJOSESigner() throws {
		let keyAgreement = P256.KeyAgreement.PrivateKey()
		let secKey = try keyAgreement.toSecKey()
		let signingInput = "Hello, World!".data(using: .utf8)!
		// jose swift uses the following code to sign the data
		let signatureDataDer = try #require(SecKeyCreateSignature(secKey, .ecdsaSignatureMessageX962SHA256, signingInput as CFData, nil) as Data?)
		let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signatureDataDer)
		let keySign = try P256.Signing.PrivateKey(x963Representation: keyAgreement.x963Representation)
	    #expect(keySign.publicKey.isValidSignature(ecdsaSignature, for: signingInput), "Signature is invalid")
	}

	@Test("Algorithm conversion supports string names", arguments: [
		("ES256", JWSAlgorithm.AlgorithmType.ES256),
		("ES384", JWSAlgorithm.AlgorithmType.ES384),
		("ES512", JWSAlgorithm.AlgorithmType.ES512),
		("EdDSA", JWSAlgorithm.AlgorithmType.EdDSA)
	])
	func testStringAlgorithmConversion(input: String, expected: JWSAlgorithm.AlgorithmType) throws {
		let result = OpenId4VCIService.convertToJWSAlgorithmType(input)
		#expect(result == expected, "String algorithm '\(input)' should convert to \(expected)")
	}

	@Test("Algorithm conversion supports IANA COSE integer values", arguments: [
		("-7", JWSAlgorithm.AlgorithmType.ES256),   // ECDSA w/ SHA-256
		("-34", JWSAlgorithm.AlgorithmType.ES384),  // ECDSA w/ SHA-384
		("-36", JWSAlgorithm.AlgorithmType.ES512),  // ECDSA w/ SHA-512
		("-8", JWSAlgorithm.AlgorithmType.EdDSA)    // EdDSA signature algorithms
	])
	func testCOSEIntegerAlgorithmConversion(input: String, expected: JWSAlgorithm.AlgorithmType) throws {
		let result = OpenId4VCIService.convertToJWSAlgorithmType(input)
		#expect(result == expected, "COSE integer '\(input)' should convert to \(expected)")
	}

	@Test("Algorithm conversion returns nil for invalid values", arguments: [
		"invalid-algorithm",
		"999",
		"-999",
		"",
		"RS256"  // Not supported by this implementation
	])
	func testInvalidAlgorithmConversion(input: String) throws {
		let result = OpenId4VCIService.convertToJWSAlgorithmType(input)
		#expect(result == nil, "Invalid algorithm '\(input)' should return nil")
	}

	@Test("Direct COSE algorithm conversion", arguments: [
		(-7, JWSAlgorithm.AlgorithmType.ES256),
		(-34, JWSAlgorithm.AlgorithmType.ES384),
		(-36, JWSAlgorithm.AlgorithmType.ES512),
		(-8, JWSAlgorithm.AlgorithmType.EdDSA)
	])
	func testDirectCOSEAlgorithmConversion(input: Int, expected: JWSAlgorithm.AlgorithmType) throws {
		let result = OpenId4VCIService.coseAlgorithmToJWSAlgorithmType(input)
		#expect(result == expected, "COSE algorithm \(input) should convert to \(expected)")
	}

	@Test("Direct COSE algorithm conversion returns nil for unsupported values", arguments: [
		-1, -2, -3, -4, -5, -6, -9, -10, 1, 2, 3, 999, -999
	])
	func testUnsupportedCOSEAlgorithmConversion(input: Int) throws {
		let result = OpenId4VCIService.coseAlgorithmToJWSAlgorithmType(input)
		#expect(result == nil, "Unsupported COSE algorithm \(input) should return nil")
	}

	@Test("Integration test: Mixed algorithm formats in credential metadata")
	func testMixedAlgorithmFormatsIntegration() throws {
		// Simulate credential metadata with both string and COSE integer formats
		let mixedAlgorithms: Set<String> = ["ES256", "-34", "EdDSA", "-7"]
		let convertedAlgorithms = mixedAlgorithms.compactMap { OpenId4VCIService.convertToJWSAlgorithmType($0) }
		
		// Should successfully convert all 4 algorithms (even though ES256 appears twice)
		#expect(convertedAlgorithms.count == 4, "Should convert all 4 algorithm values")
		
		// Check that all expected algorithms are present
		let expectedAlgorithms: Set<JWSAlgorithm.AlgorithmType> = [.ES256, .ES384, .EdDSA]
		let actualAlgorithms = Set(convertedAlgorithms)
		
		#expect(actualAlgorithms == expectedAlgorithms, "Should contain ES256, ES384, and EdDSA")
	}

	@Test("Error handling: Empty algorithm set should be handled gracefully")
	func testEmptyAlgorithmSet() throws {
		let emptyAlgorithms: Set<String> = []
		let convertedAlgorithms = emptyAlgorithms.compactMap { OpenId4VCIService.convertToJWSAlgorithmType($0) }
		
		#expect(convertedAlgorithms.isEmpty, "Empty input should result in empty output")
	}


	}
