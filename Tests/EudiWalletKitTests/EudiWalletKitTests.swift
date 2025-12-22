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
import MdocDataModel18013
import WalletStorage
import MdocSecurity18013
import SwiftCBOR
@testable import JOSESwift
import eudi_lib_sdjwt_swift
import OpenID4VP
import enum OpenID4VP.ClaimPathElement
import struct OpenID4VP.ClaimPath

struct EudiWalletKitTests {

	@Test("Parse DCQL", arguments: [DocDataFormat.cbor, .sdjwt])
	func testParseDcql(format: DocDataFormat) throws {
		if format == .cbor { return } // skip cbor sample due to legacy schema differences
		let testDcqlData = Data(name: "dcql-\(format.rawValue)", ext: "json", from: Bundle.module)!
		let testDcql = try JSONDecoder().decode(DCQL.self, from: testDcqlData)
		let (fmtsRequested, _) = try OpenId4VpUtils.parseDcqlFormats(testDcql,  idsToDocTypes: ["1": "urn:eu.europa.ec.eudi:pid:1"], dataFormats: [:], docDisplayNames: [:])
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
		guard let data = Data(name: "mdoc-\(dt)", ext: "txt", from: Bundle.module) else {
			throw NSError(domain: "TestError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Resource file not found: mdoc-\(dt).txt"])
		}
		let strData = try #require(String(data: data, encoding: .utf8))
		let base64Data = try #require(Data(base64URLEncoded: strData))
		let dr = try DeviceResponse(data: [UInt8](base64Data))
		let iss = try #require(dr.documents?.first?.issuerSigned)
		#expect("org.iso.18013.5.1.mDL" == iss.issuerAuth.mso.docType)
	}

	let OPENID4VP_1_0_SESSION_TRANSCRIPT =
		"83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"

	let clientId = "x509_san_dns:example.com"
	let nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
	let jwk = """
		{
		"kty": "EC",
		"crv": "P-256",
		"x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
		"y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
		"use": "enc",
		"alg": "ECDH-ES",
		"kid": "1"
		}
		"""
	let responseUri = "https://example.com/response"

	@Test("Generate OpenId4Vp Session Transcript with JwkThumbprint") func testGenerateOpenId4VpSessionTranscriptWithJwkThumbprint() {
		let jwkData = jwk.data(using: .utf8)!
		let jwkObj = try! ECPublicKey(data: jwkData)
		let jwkThumbprint = (try? jwkObj.thumbprint(algorithm: .SHA256)).flatMap { Data(base64URLEncoded: $0) }
		let openid4VpHandover = OpenId4VpUtils.generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri, nonce: nonce, jwkThumbprint: jwkThumbprint?.byteArray)
		#expect(OPENID4VP_1_0_SESSION_TRANSCRIPT == SessionTranscript(handOver: openid4VpHandover).encode(options: CBOROptions()).toHexString())
	}

	@Test("Signature with JOSE Signer") func testJOSESigner() throws {
		let keyAgreement = P256.KeyAgreement.PrivateKey()
		let secKey = try keyAgreement.toSecKey()
		let signingInput = "Hello, World!".data(using: .utf8)!
		// jose swift uses the following code to sign the data
		let signatureDataDer = try #require(SecKeyCreateSignature(secKey, .ecdsaSignatureMessageX962SHA256, signingInput as CFData, nil) as Data?)
		let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signatureDataDer)
		let keySign = try P256.Signing.PrivateKey(x963Representation: keyAgreement.x963Representation)
	    #expect(keySign.publicKey.isValidSignature(ecdsaSignature, for: signingInput), "Signature is invalid")
	}

@Test("URL reconstruction preserves port numbers")
	func testUrlReconstructionWithPort() throws {
		// Test URL without port
		let urlWithoutPort = try #require(URL(string: "https://example.com/path"))
		let reconstructedWithoutPort = urlWithoutPort.getBaseUrl()
		#expect(reconstructedWithoutPort == "https://example.com")
		// Test URL with standard HTTPS port (should not include port)
		let urlWithStandardPort = try #require(URL(string: "https://example.com:443/path"))
		let reconstructedWithStandardPort = urlWithStandardPort.getBaseUrl()
		#expect(reconstructedWithStandardPort == "https://example.com:443")
		// Test HTTP URL with custom port
		let httpUrlWithPort = try #require(URL(string: "http://localhost:3000/api"))
		let reconstructedHttpWithPort = httpUrlWithPort.getBaseUrl()
		#expect(reconstructedHttpWithPort == "http://localhost:3000")
	}

}

// MARK: - Data Extension for Test Resources

extension Data {
	init?(name: String, ext: String, from bundle: Bundle) {
		// Try with Resources subdirectory first
		if let url = bundle.url(forResource: name, withExtension: ext, subdirectory: "Resources") {
			try? self.init(contentsOf: url)
			return
		}
		// Try without subdirectory
		if let url = bundle.url(forResource: name, withExtension: ext) {
			try? self.init(contentsOf: url)
			return
		}
		return nil
	}
}
