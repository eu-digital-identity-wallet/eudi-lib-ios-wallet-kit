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
import OpenID4VCI
import X509
import enum OpenID4VP.ClaimPathElement
import struct OpenID4VP.ClaimPath
import protocol OpenID4VCI.Networking

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

	@Test("CBOR docClaims order follows metadata claim order")
	func testCborDocClaimsRespectMetadataOrder() throws {
		// 1. Load issuer metadata and extract claim paths for pid-mso-mdoc
		let issuerData = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
		let issuerJson = try JSON(data: issuerData)
		let claimsJson = try #require(issuerJson["credential_configurations_supported"]["pid-mso-mdoc"]["credential_metadata"]["claims"].array)

		let claimMetadata = claimsJson.compactMap { claimJson -> DocClaimMetadata? in
			guard let path = claimJson["path"].array?.map(\.stringValue) else { return nil }
			let displayArr = claimJson["display"].array?.compactMap { d -> DisplayMetadata? in
				guard let name = d["name"].string else { return nil }
				return DisplayMetadata(name: name, localeIdentifier: d["locale"].string, logo: nil, description: nil, backgroundColor: nil, textColor: nil)
			}
			return DocClaimMetadata(display: displayArr, isMandatory: claimJson["mandatory"].bool, claimPath: path)
		}
		#expect(!claimMetadata.isEmpty)

		// 2. Load the current (pre-reorder) doc claims
		let claimsData = try #require(Data(name: "pid_demo_current_doc_claims_order", ext: "json", from: Bundle.module))
		let currentClaimsJson = try #require(try JSON(data: claimsData).array)

		let docClaims = currentClaimsJson.enumerated().map { index, claim in
			DocClaim(
				name: claim["name"].stringValue,
				path: claim["path"].arrayValue.map(\.stringValue),
				displayName: claim["displayName"].string,
				dataValue: .string(claim["stringValue"].stringValue),
				stringValue: claim["stringValue"].stringValue,
				isOptional: claim["isOptional"].boolValue,
				order: index,
				namespace: claim["namespace"].string
			)
		}
		#expect(docClaims.count == currentClaimsJson.count)

		// 3. Build model and document with metadata
		let docType = "eu.europa.ec.eudi.pid.1"
		let metadata = DocMetadata(
			credentialIssuerIdentifier: issuerJson["credential_issuer"].stringValue,
			configurationIdentifier: "pid-mso-mdoc",
			docType: docType,
			display: nil,
			issuerDisplay: nil,
			claims: claimMetadata,
			authorizedRequestData: nil,
			keyOptions: nil,
			credentialOptions: nil
		)

		let model = DocClaimsModel(configuration: DocClaimsModelConfiguration(
			id: UUID().uuidString, docType: docType, displayName: nil, display: nil,
			credentialIssuerIdentifier: nil, configurationIdentifier: nil,
			validFrom: nil, validUntil: nil, statusIdentifier: nil,
			credentialsUsageCounts: nil, credentialPolicy: .rotateUse,
			secureAreaName: nil, modifiedAt: nil,
			docClaims: docClaims, docDataFormat: .cbor, hashingAlg: nil
		))

		let document = WalletStorage.Document(
			id: model.id, docType: docType, docDataFormat: .cbor,
			data: Data(), docKeyInfo: nil, createdAt: .now, modifiedAt: .now,
			metadata: metadata.toData(), displayName: nil, status: .issued
		)

		// 4. Apply reordering
		let reordered = StorageManager.reorderDocClaimsByMetadata(model, doc: document, uiCulture: nil)

		// 5. Verify claims are now in metadata order
		let expectedOrder = claimMetadata
			.filter { meta in docClaims.contains { $0.path == meta.claimPath } }
			.map { $0.claimPath.last! }

		let actualOrder = reordered.docClaims.map(\.name)
		#expect(actualOrder == expectedOrder)

		// Verify order values are sequential
		for (i, claim) in reordered.docClaims.enumerated() {
			#expect(claim.order == i)
		}
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

	@Test("Issued SD-JWT credentials are validated before storage")
	func testValidateIssuedSdJwtCredential() async throws {
		let storageService = TestDataStorageService()
		let service = try makeVciService(storageService: storageService)
		let document = try makeSdJwtDocument(fromResource: "sjwt-pid")
		try await service.validateIssuedDocuments(document, batch: nil, publicKeys: [])
	}

	private func makeVciService(
		storageService: TestDataStorageService,
		issuerURL: String = "https://credential-issuer.example.com"
	) throws -> OpenId4VCIService {
		let networking = TestNetworking(metadata: try makeSdJwtIssuerMetadata(forResource: "sjwt-pid", issuerURL: issuerURL))
		let storage = StorageManager(storageService: storageService)
		let eudic = ["pidissuerca02_ut"].compactMap { SecCertificateCreateWithData(nil, Data(name: $0, ext: "der", from: Bundle.module)! as CFData)! }
		let config = OpenId4VciConfiguration(credentialIssuerURL: issuerURL, requirePAR: true, requireDpop: true, trustedIssuerCertificates: [eudic])
		return try OpenId4VCIService(uiCulture: nil, config: config, networking: networking, storage: storage, storageService: storageService)
	}

	private func makeSdJwtDocument(
		fromResource resourceName: String,
		transform: ((String) throws -> String)? = nil
	) throws -> WalletStorage.Document {
		let original = try #require(String(data: Data(name: resourceName, ext: "txt", from: Bundle.module)!, encoding: .utf8))
		let serialized = try transform?(original) ?? original
		return WalletStorage.Document(id: UUID().uuidString, docType: "urn:eu:europa:ec:eudi:pid:1", docDataFormat: .sdjwt,
			data: Data(serialized.utf8), docKeyInfo: nil, createdAt: .now, metadata: nil, displayName: nil, status: .issued)
	}

	private func makeSdJwtIssuerMetadata(forResource resourceName: String, issuerURL: String) throws -> Data {
		let serialized = try #require(String(data: Data(name: resourceName, ext: "txt", from: Bundle.module)!, encoding: .utf8))
		let issuerJwkData = try makeIssuerJwkData(from: serialized)
		let ec = try issuerJwkData.ecPublicKeyComponents()
		let metadata: [String: Any] = ["issuer": issuerURL,
			"jwks": [ "keys": ["crv": ec.crv, "x": ec.x.base64URLEncodedString(), "y": ec.y.base64URLEncodedString(), "use": "sig"] ] ]
		return try JSONSerialization.data(withJSONObject: metadata)
	}

	private func makeIssuerJwkData(from serialized: String) throws -> Data {
		let (header, _, _) = StorageManager.extractJWTParts(serialized)
		let headerData = try #require(Data(base64URLEncoded: header))
		let headerJson = try JSON(data: headerData)
		let certificateBase64 = try #require(headerJson["x5c"].array?.first?.string)
		let certificateData = try #require(Data(base64Encoded: certificateBase64))
		let certificate = try Certificate(derEncoded: [UInt8](certificateData))
		let keyData = Data(certificate.publicKey.subjectPublicKeyInfoBytes)
		return keyData
	}
}

// MARK: - Data Extension for Test Resources

actor TestDataStorageService: DataStorageService {
	func loadDocument(id: String, status: WalletStorage.DocumentStatus) async throws -> WalletStorage.Document? { nil }
	func loadDocumentMetadata(id: String) async throws -> DocMetadata? { nil }
	func loadDocuments(status: WalletStorage.DocumentStatus) async throws -> [WalletStorage.Document]? { [] }
	func saveDocument(_ document: WalletStorage.Document, batch: [WalletStorage.Document]?, allowOverwrite: Bool) async throws {}
	func deleteDocument(id: String, status: WalletStorage.DocumentStatus) async throws {}
	func deleteDocuments(status: WalletStorage.DocumentStatus) async throws {}
	func deleteDocumentCredential(id: String, index: Int) async throws {}
}

final class TestNetworking: Networking {
	private let metadata: Data

	init(metadata: Data) {
		self.metadata = metadata
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: [:])!
		return (metadata, response)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		try await data(from: request.url ?? URL(string: "https://example.com")!)
	}
}

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
