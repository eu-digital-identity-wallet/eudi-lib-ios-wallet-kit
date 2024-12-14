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
import SwiftCBOR
@testable import JOSESwift
import eudi_lib_sdjwt_swift

struct EudiWalletKitTests {

	@Test func testParsePresentationDefinition() throws {
		let testPD = try JSONDecoder().decode(PresentationDefinition.self, from: Data(name: "mdocPresDef", ext: "json", from: Bundle.module)! )
		let (items, fmt) = try Openid4VpUtils.parsePresentationDefinition(testPD)
		let items1 = try #require(items)
		#expect(!items1.keys.isEmpty)
		#expect(fmt == .cbor)
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
	
	@Test func testParseSdJwt() throws {
		let data = Data(name: "sd-jwt", ext: "txt", from: Bundle.module)! 
		let parser = CompactParser()
    	let sdJwt = try parser.getSignedSdJwt(serialisedString: String(data: data, encoding: .utf8)!)
    
    // When
    //let json = try sdJwt.asJwsJsonObject( option: .general,  kbJwt: sdJwt.kbJwt?.compactSerialization, getParts: parser.extractJWTParts)
		let result  = try sdJwt.recreateClaims()
		print("result: \(result.recreatedClaims)")
		
		}
	}
