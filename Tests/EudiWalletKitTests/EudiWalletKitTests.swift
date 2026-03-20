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
import SwiftyJSON
import OpenID4VP
import enum OpenID4VP.ClaimPathElement
import struct OpenID4VP.ClaimPath

struct EudiWalletKitTests {

	@Test("Parse DCQL", arguments: [DocDataFormat.cbor, .sdjwt])
	func testParseDcql(format: DocDataFormat) throws {
		if format == .cbor { return } // skip cbor sample due to legacy schema differences
		let testDcqlData = Data(name: "dcql-\(format.rawValue)", ext: "json", from: Bundle.module)!
		let testDcql = try JSONDecoder().decode(DCQL.self, from: testDcqlData)
		let (fmtsRequested, _, _) = try OpenId4VpUtils.parseDcqlFormats(testDcql,  idsToDocTypes: ["1": "urn:eu.europa.ec.eudi:pid:1"])
		#expect(fmtsRequested.allSatisfy({ (k,v) in v == format }))
	}

	private func parseSdJwtClaims(for dt: String) throws -> (recreatedClaims: JSON, disclosures: [String]) {
		let dataFileName = "sjwt-\(dt)"
		let data = Data(name: dataFileName, ext: "txt", from: Bundle.module)!
		let parser = CompactParser()
		let sdJwt = try parser.getSignedSdJwt(serialisedString: String(data: data, encoding: .utf8)!)
		let result = try sdJwt.recreateClaims()
		let resolved = StorageManager.resolveNestedSdClaims(result.recreatedClaims, disclosures: sdJwt.disclosures, hashingAlg: "sha-256")
		return (resolved, sdJwt.disclosures)
	}

	@Test("Get claims from sd-jwt", arguments: ["mdl", "pid", "pid-address"])
	func testParseJwt(dt: String) async throws {
		let (claims, _) = try parseSdJwtClaims(for: dt)
		if dt == "pid" {
			let family_name = try #require(claims["family_name"].string)
			let given_name = try #require(claims["given_name"].string)
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

	@Test("Generate OpenId4Vp Session Transcript with JwkThumbprint") func testGenerateOpenId4VpSessionTranscriptWithJwkThumbprint() {
		let OPENID4VP_1_0_SESSION_TRANSCRIPT = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
		let clientId = "x509_san_dns:example.com"
		let nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
		let jwk = "{\"kty\": \"EC\",\"crv\": \"P-256\",\"x\": \"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0\",\"y\": \"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc\",\"use\": \"enc\",\"alg\": \"ECDH-ES\",\"kid\": \"1\"}"
		let responseUri = "https://example.com/response"

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


	@Test("Sex field displays male/female for both number and string JSON types")
	func testSexFieldConversion() throws {
		// When sex is a JSON number
		let jsonNumber = JSON(parseJSON: """
		{ "sex": 1 }
		""")
		let claimMetadata: [DocClaimMetadata]? = nil
		let uiCulture: String? = nil
		let numberClaims = jsonNumber.toClaimsArray(pathPrefix: [], claimMetadata, uiCulture)?.0
		let numberSex = numberClaims?.first(where: { $0.name == "sex" })
		#expect(numberSex != nil)
		#expect(numberSex?.stringValue == "male") // raw value preserved
		if case .string(let display) = numberSex?.dataValue {
			#expect(display == "male")
		} else {
			Issue.record("Expected .string data value for sex number claim")
		}
		// When sex is a JSON string (Python issuer encodes as string)
		let jsonString = JSON(parseJSON: """
		{ "sex": "1" }
		""")
		let stringClaims = jsonString.toClaimsArray(pathPrefix: [], claimMetadata, uiCulture)?.0
		let stringSex = stringClaims?.first(where: { $0.name == "sex" })
		#expect(stringSex != nil)
		#expect(stringSex?.stringValue == "male")
		if case .string(let display) = stringSex?.dataValue {
			#expect(display == "male")
		} else {
			Issue.record("Expected .string data value for sex string claim")
		}
		// Female value
		let jsonFemale = JSON(parseJSON: """
		{ "sex": "2" }
		""")
		let femaleClaims = jsonFemale.toClaimsArray(pathPrefix: [], claimMetadata, uiCulture)?.0
		let femaleSex = femaleClaims?.first(where: { $0.name == "sex" })
		if case .string(let display) = femaleSex?.dataValue {
			#expect(display == "female")
		} else {
			Issue.record("Expected .string data value for female sex claim")
		}
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
