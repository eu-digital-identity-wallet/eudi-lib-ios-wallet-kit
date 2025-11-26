/*
 *  Copyright (c) 2023-2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import Foundation
import SwiftCBOR
import CryptoKit
import Logging
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import eudi_lib_sdjwt_swift
import WalletStorage
import JSONWebSignature
@preconcurrency import JSONWebAlgorithms
import SiopOpenID4VP
import enum SiopOpenID4VP.ClaimPathElement
import SwiftyJSON

class Openid4VpUtils {
	//  example path: "$['eu.europa.ec.eudiw.pid.1']['family_name']"
	static let pathNsItemRx = try! NSRegularExpression(pattern: #"\$\['([^']+)'\]\['([^']+)'\]"#, options: .caseInsensitive)
	// example path: $.given_name_national_character
	static let pathItemRx: NSRegularExpression = try! NSRegularExpression(pattern: #"\$\.(.+)"#, options: .caseInsensitive)

	static func generateSessionTranscript(clientId: String,	responseUri: String, nonce: String, jwkThumbprint: String? = nil) -> SessionTranscript {
		let openID4VPHandover = generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri,	nonce: nonce, jwkThumbprint: jwkThumbprint)
		return SessionTranscript(handOver: openID4VPHandover)
	}


	/// Generate the `SessionTranscript` CBOR where the presentation request is invoked using redirects.
	/// - Parameters:
	///   - clientId: The `client_id` request parameter. If applicable, this includes the Client Identifier Prefix.
	///   - responseUri: Either the `redirect_uri` or `response_uri` request parameter, depending on which is present, as determined by the Response Mode.
	///   - nonce: The value of the `nonce` request parameter.
	///   - jwkThumbprint: If the response is encrypted, e.g., using `direct_post.jwt`, this element must be the JWK SHA-256 Thumbprint of the Verifier's public key used to encrypt the response. Otherwise `nil`.
	/// - Returns: A CBOR representation of the OpenID4VPHandover structure.
	/// - Remark: See [Handover and SessionTranscript Definitions](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-handover-and-sessiontranscript).
	static func generateOpenId4VpHandover(clientId: String,	responseUri: String, nonce: String, jwkThumbprint: String? = nil) -> CBOR {
		var openID4VPHandoverInfo: [UInt8]
		
		if let jwkThumbprint = jwkThumbprint {
			let openID4VPHandoverInfoToHash = CBOR.array([.utf8String(clientId), .utf8String(nonce), .utf8String(jwkThumbprint), .utf8String(responseUri)])
			openID4VPHandoverInfo = [UInt8](SHA256.hash(data: openID4VPHandoverInfoToHash.asData()))
		}
		else {
			let openID4VPHandoverInfoToHash = CBOR.array([.utf8String(clientId), .utf8String(nonce), .null, .utf8String(responseUri)])
			openID4VPHandoverInfo = [UInt8](SHA256.hash(data: openID4VPHandoverInfoToHash.asData()))
		}
		
		return CBOR.array(["OpenID4VPHandover", .byteString(openID4VPHandoverInfo)])
	}

	static func generateMdocGeneratedNonce() -> String {
		var bytes = [UInt8](repeating: 0, count: 16)
		let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
		if result != errSecSuccess {
			logger.warning("Problem generating random bytes with SecRandomCopyBytes")
			bytes = (0 ..< 16).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) }
		}
		return Data(bytes).base64URLEncodedString()
	}

	/// Parse DCQL into request items (docType -> namespaced items), formats requested (docType -> dataFormat) and input descriptor map (docType -> credentialQueryId)
	static func parseDcql(_ dcql: DCQL, idsToDocTypes: [String: String], dataFormats: [String: DocDataFormat], docDisplayNames: [String: [String: [String: String]]?], logger: Logger? = nil) throws -> (RequestItems?, [String: DocDataFormat], [String: String]) {
		var inputDescriptorMap = [String: String]()
		var requestItems = RequestItems()
		var formatsRequested = [String: DocDataFormat]()
		for credQuery in dcql.credentials {
			let formatRequested: DocDataFormat = credQuery.dataFormat
			guard let docType = credQuery.docType else { continue }
			if !idsToDocTypes.values.contains(docType) {
				logger?.warning("Document type \(docType) not in supported document types \(idsToDocTypes.values)")
				// todo: implement full support for credentialSets
				if dcql.credentialSets == nil { throw WalletError(description: "Document type \(docType) not in supported document types \(idsToDocTypes.values)") }
			}
			var nsItems: [String: [RequestItem]] = [:]
			for claim in credQuery.claims ?? [] {
				guard let pair =  Self.parseClaim(claim, formatRequested) else { continue }
				if nsItems[pair.0] == nil { nsItems[pair.0] = [] }
				if !nsItems[pair.0]!.contains(pair.1) { nsItems[pair.0]!.append(pair.1) }
			}
			inputDescriptorMap[docType] = credQuery.id.value; requestItems[docType] = nsItems; formatsRequested[docType] = formatRequested
		}
		return (requestItems, formatsRequested, inputDescriptorMap)
	}

	/// parse claim-query and return (namespace, itemIdentifier) pair
	static func parseClaim(_ claim: ClaimsQuery, _ docDataFormat: DocDataFormat) -> (String, RequestItem)? {
		if docDataFormat == .cbor {
			let ns = claim.path.component1().description
			let itemIdentifier = claim.path.component2()?.head().description
			return if let itemIdentifier { (ns, RequestItem(elementPath: [itemIdentifier], intentToRetain: claim.intentToRetain, isOptional: false)) } else { nil }
		} else if docDataFormat == .sdjwt {
			let elementPath = claim.path.value.compactMap(\.claimName)
			return ("", RequestItem(elementPath: elementPath, intentToRetain: false, isOptional: false))
		}
		return nil
	}

	static func getSdJwtPresentation(_ sdJwt: SignedSDJWT, hashingAlg: HashingAlgorithm, signer: SecureAreaSigner, signAlg: JSONWebAlgorithms.SigningAlgorithm, requestItems: [RequestItem], nonce: String, aud: String, transactionData: [TransactionData]?) async throws -> SignedSDJWT? {
		guard let allPathsDict = (try sdJwt.recreateClaims()).disclosuresPerClaimPath else { throw WalletError(description: "No disclosures found") }
		let allPaths = Array(allPathsDict.keys)
		let requestPaths = requestItems.map(\.elementPath)
		let query = Set(allPaths.filter { path in requestPaths.contains(where: { r in r.contains(path.value.compactMap(\.claimName)) }) })
		let presentedSdJwt = try await sdJwt.present(query: query)
		guard let presentedSdJwt else { return nil }
		let digestCreator = DigestCreator(hashingAlgorithm: hashingAlg)
		guard let sdHash = digestCreator.hashAndBase64Encode(input: CompactSerialiser(signedSDJWT: presentedSdJwt).serialised) else { return nil }
    	var payload = [Keys.nonce.rawValue: nonce, Keys.aud.rawValue: aud, Keys.iat.rawValue: Int(Date().timeIntervalSince1970.rounded()), Keys.sdHash.rawValue: sdHash] as [String : Any]
		  // Process transaction data hashes if available
		if let transactionData, !transactionData.isEmpty {
			let transactionDataHashes = transactionData.map { td -> String in
				switch td {	case .sdJwtVc(let v): return sha256Hash(v) }
			}
			payload["transaction_data_hashes_alg"] = "sha-256"
			payload["transaction_data_hashes"] = transactionDataHashes
		}
		let kbJwt: KBJWT = try KBJWT(header: DefaultJWSHeaderImpl(algorithm: signAlg), kbJwtPayload: JSON(payload))
		let holderPresentation = try await SDJWTIssuer.presentation(holdersPrivateKey: signer, signedSDJWT: presentedSdJwt, disclosuresToPresent: presentedSdJwt.disclosures, keyBindingJWT: kbJwt)
		return holderPresentation
	}

	static func sha256Hash(_ input: String) -> String {
		let inputData = Array(input.utf8)
		let digest = SHA256.hash(data: inputData)
		return Data(digest).base64URLEncodedString()
	}

	static func filterSignedJwtByDocType(_ sdJwt: SignedSDJWT, docType: String) -> Bool {
		guard let paths = try? sdJwt.recreateClaims() else { return false }
		let type = paths.recreatedClaims["vct"].string ?? paths.recreatedClaims["type"].string
		guard let type, !type.isEmpty else { return false }
		return vctToDocTypeMatch(docType, type)
	}

	static func vctToDocType(_ vct: String) -> String { vct.replacingOccurrences(of: "urn:", with: "").replacingOccurrences(of: ":", with: ".") }

	static func vctToDocTypeMatch(_ s1: String, _ s2: String) -> Bool {
		Openid4VpUtils.vctToDocType(s1).hasPrefix(Openid4VpUtils.vctToDocType(s2)) || Openid4VpUtils.vctToDocType(s2).hasPrefix(Openid4VpUtils.vctToDocType(s1))
	}
}

extension ClaimPathElement {
	public var claimName: String? {
		if case .claim(let name) = self { name } else { nil }
	}
}

extension CoseEcCurve {
	init?(crvName: String) {
		switch crvName {
		case "P-256": self = .P256
		case "P-384": self = .P384
		case "P-512": self = .P521
		default: return nil
		}
	}
}


extension CredentialQuery {
	public var docType: String? {
		let metaDocType = meta.dictionaryObject?.first?.value
		let docType = metaDocType as? String ?? (metaDocType as? [String])?.first
		return docType
	}

	public var dataFormat: DocDataFormat {
		format.format == "mso_mdoc"  ? .cbor : .sdjwt
	}
}

extension DCQL {
	public func findQuery(id: String) -> CredentialQuery? {
		credentials.first { $0.id.value == id }
	}
}
