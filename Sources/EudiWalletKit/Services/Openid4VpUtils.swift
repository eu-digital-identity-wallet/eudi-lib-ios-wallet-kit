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
import PresentationExchange
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import eudi_lib_sdjwt_swift
import WalletStorage
import JSONWebSignature
import JSONWebAlgorithms
import SiopOpenID4VP
import SwiftyJSON
/**
 *  Utility class to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = nil,
 *  EReaderKeyBytes = nil
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = Data
 *  responseUriHash = Data
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = String
 *  clientId = String
 *  responseUri = String
 *  nonce = String
 *
 */

class Openid4VpUtils {
	//  example path: "$['eu.europa.ec.eudiw.pid.1']['family_name']"
	static let pathNsItemRx = try! NSRegularExpression(pattern: #"\$\['([^']+)'\]\['([^']+)'\]"#, options: .caseInsensitive)
	// example path: $.given_name_national_character
	static let pathItemRx: NSRegularExpression = try! NSRegularExpression(pattern: #"\$\.(.+)"#, options: .caseInsensitive)

	static func generateSessionTranscript(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> SessionTranscript {
		let openID4VPHandover = generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri,	nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce)
		return SessionTranscript(handOver: openID4VPHandover)
	}

	static func generateOpenId4VpHandover(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> CBOR {
		let clientIdToHash = CBOR.encodeArray([clientId, mdocGeneratedNonce])
		let responseUriToHash = CBOR.encodeArray([responseUri, mdocGeneratedNonce])

		let clientIdHash = [UInt8](SHA256.hash(data: clientIdToHash))
		let responseUriHash = [UInt8](SHA256.hash(data: responseUriToHash))

		return CBOR.array([.byteString(clientIdHash), .byteString(responseUriHash), .utf8String(nonce)])
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

	static func parseDcql(_ dcql: DCQL, idsToDocTypes: [String: String], dataFormats: [String: DocDataFormat], docDisplayNames: [String: [String: [String: String]]?], logger: Logger? = nil) throws -> (RequestItems?, [String: DocDataFormat], [String: String]) {
		var inputDescriptorMap = [String: String]()
		var requestItems = RequestItems()
		var formatsRequested = [String: DocDataFormat]()
		for credQuery in dcql.credentials {
			let formatRequested: DocDataFormat = credQuery.format.format == "mso_mdoc"  ? .cbor : .sdjwt
			let metaDocType = credQuery.meta?.dictionaryObject?.first?.value
			guard let docType = metaDocType as? String ?? (metaDocType as? [String])?.first else { continue }
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
			let ns = claim.namespace?.namespace ?? claim.path?.component1().description
			let itemIdentifier = claim.claimName?.claimName ?? claim.path?.component2()?.head().description
			return if let ns, let itemIdentifier { (ns, RequestItem(elementPath: [itemIdentifier], intentToRetain: false, isOptional: false)) } else { nil }
		} else if docDataFormat == .sdjwt {
			let elementPath = claim.path?.value.map(\.description)
			return if let elementPath { ("", RequestItem(elementPath: elementPath, intentToRetain: false, isOptional: false)) } else { nil }
		}
		return nil
	}

	/// Parse mDoc request from presentation definition (Presentation Exchange 2.0.0 protocol)
	/// dataFormats: map of document-id to data format
	static func parsePresentationDefinition(_ presentationDefinition: PresentationDefinition, idsToDocTypes: [String: String], dataFormats: [String: DocDataFormat], docDisplayNames: [String: [String: [String: String]]?], logger: Logger? = nil) throws -> (RequestItems?, [String: DocDataFormat], [String: String]) {
		var inputDescriptorMap = [String: String]()
		var requestItems = RequestItems()
		var formatsRequested = [String: DocDataFormat]()
		for inputDescriptor in presentationDefinition.inputDescriptors {
			let formatRequested: DocDataFormat = inputDescriptor.formatContainer?.formats.contains(where: { $0["designation"].string?.lowercased() == "mso_mdoc" }) ?? false ? .cbor : .sdjwt
			let filterValue = inputDescriptor.constraints.fields.first { $0.filter?["const"].string != nil }?.filter?["const"].string
			let docType = filterValue ?? inputDescriptor.id.trimmingCharacters(in: .whitespacesAndNewlines)
			let pathRx = formatRequested == .cbor ? Openid4VpUtils.pathNsItemRx : Openid4VpUtils.pathItemRx
			var nsItems: [String: [RequestItem]] = [:]
			for field in inputDescriptor.constraints.fields {
				guard let pair =  Self.parseField(field, pathRx: pathRx, regexParts: formatRequested == .cbor ? 2 : 1) else { continue }
				if nsItems[pair.0] == nil { nsItems[pair.0] = [] }
				if !nsItems[pair.0]!.contains(pair.1) { nsItems[pair.0]!.append(pair.1) }
			}
			if !nsItems.isEmpty { inputDescriptorMap[docType] = inputDescriptor.id; requestItems[docType] = nsItems; formatsRequested[docType] = formatRequested }
		}
		return (requestItems, formatsRequested, inputDescriptorMap)
	}

	/// parse field and return (namespace, RequestItem) pair
	static func parseField(_ field: Field, pathRx: NSRegularExpression, regexParts: Int) -> (String, RequestItem)? {
		guard let path = field.paths.first else { return nil }
		guard let nsItemPair = regexParts == 2 ? parsePath2(path, pathRx: pathRx) : parsePath1(path, pathRx: pathRx) else { return nil }
		let elementPath = nsItemPair.1.components(separatedBy: ".")
		return (nsItemPair.0, RequestItem(elementPath: elementPath, intentToRetain: field.intentToRetain ?? false, isOptional: field.optional ?? false))
	}

	/// parse path and return (namespace, itemIdentifier) pair for jwt format
	static func parsePath1(_ path: String, pathRx: NSRegularExpression) -> (String, String)? {
		guard let match = pathRx.firstMatch(in: path, options: [], range: NSRange(location: 0, length: path.utf16.count)) else { return nil }
		let r2 = match.range(at: 1)
		let r2l = path.index(path.startIndex, offsetBy: r2.location)
		let r2r = path.index(r2l, offsetBy: r2.length)
		let fieldName = String(path[r2l..<r2r])
		// take parent only for now
		return ("", fieldName)
	}

	/// parse path and return (namespace, itemIdentifier) pair
	static func parsePath2(_ path: String, pathRx: NSRegularExpression) -> (String, String)? {
		guard let match = pathRx.firstMatch(in: path, options: [], range: NSRange(location: 0, length: path.utf16.count)) else { return nil }
		let r1 = match.range(at:1);
		let r1l = path.index(path.startIndex, offsetBy: r1.location)
		let r1r = path.index(r1l, offsetBy: r1.length)
		let r2 = match.range(at: 2)
		let r2l = path.index(path.startIndex, offsetBy: r2.location)
		let r2r = path.index(r2l, offsetBy: r2.length)
		return (String(path[r1l..<r1r]), String(path[r2l..<r2r]))
	}

	static func getSdJwtPresentation(_ sdJwt: SignedSDJWT, hashingAlg: HashingAlgorithm, signer: SecureAreaSigner, signAlg: JSONWebAlgorithms.SigningAlgorithm, requestItems: [RequestItem], nonce: String, aud: String, transactionData: [TransactionData]?) async throws -> SignedSDJWT? {
		let allPaths = try sdJwt.disclosedPaths()
		let requestPaths = requestItems.map(\.elementPath)
		let query = Set(allPaths.filter { path in requestPaths.contains(where: { r in r.contains(path.tokenArray) }) })
		if query.isEmpty { throw WalletError(description: "No items to present found") }
		let presentedSdJwt = try await sdJwt.present(query: query)
		guard let presentedSdJwt else { return nil }
		let digestCreator = DigestCreator(hashingAlgorithm: hashingAlg)
		guard let sdHash = digestCreator.hashAndBase64Encode(input: CompactSerialiser(signedSDJWT: presentedSdJwt).serialised) else { return nil }
    	var payload = [Keys.nonce.rawValue: nonce, Keys.aud.rawValue: aud, Keys.iat.rawValue: Int(Date().timeIntervalSince1970.rounded()), Keys.sdHash.rawValue: sdHash] as [String : Any]
		  // Process transaction data hashes if available
		if let transactionData, !transactionData.isEmpty {
			let transactionDataHashes = transactionData.map { sha256Hash($0.value) }
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

