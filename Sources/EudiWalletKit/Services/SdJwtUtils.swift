/*
 Copyright (c) 2026 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Foundation
import MdocDataModel18013
import WalletStorage
import CryptoKit
import Logging
import eudi_lib_sdjwt_swift
import SwiftyJSON
import OpenID4VCI
import JOSESwift

public final class SdJwtUtils {

	public static func toSdJwtDocModel(doc: WalletStorage.Document, uiCulture: String?, modelFactory: (any DocClaimsDecodableFactory)? = nil) -> DocClaimsModel? {
		var docClaims = [DocClaim]()
		let docMetadata: DocMetadata? = DocMetadata(from: doc.metadata)
		let docKeyInfo = DocKeyInfo(from: doc.docKeyInfo) ?? .default
		let md = docMetadata?.getMetadata(uiCulture: uiCulture)
		guard let recreatedClaims = recreateSdJwtClaims(docData: doc.data) else { return nil }
		if let cs = recreatedClaims.json.toClaimsArray(pathPrefix: [], md?.claimMetadata, uiCulture)?.0 { docClaims.append(contentsOf: cs) }
		var type = docClaims.first(where: { $0.name == "vct"})?.stringValue
		if type == nil || type!.isEmpty { type = docClaims.first(where: { $0.name == "evidence"})?.children?.first(where: { $0.name == "type"})?.stringValue }
		let validFrom: Date? = if case let .date(s) = docClaims.first(where: { $0.name == JWTClaimNames.issuedAt})?.dataValue { ISO8601DateFormatter().date(from: s) } else { nil }
		let validUntil: Date? = if case let .date(s) = docClaims.first(where: { $0.name == JWTClaimNames.expirationTime})?.dataValue { ISO8601DateFormatter().date(from: s) } else { nil }
		let statusJson = recreatedClaims.json["status"].dictionary
		let statusListJson = statusJson?["status_list"]?.dictionary
		let statusURI = statusListJson?["uri"]?.string
		let statusIndex = statusListJson?["idx"]?.int32
		let statusIdentifier: StatusIdentifier? = if let statusURI, let statusIndex { StatusIdentifier(idx: Int(statusIndex), uriString: statusURI) } else { nil }
		let credentialIssuerIdentifier = md?.credentialIssuerIdentifier
		let configurationIdentifier = md?.configurationIdentifier
		let displayName = docMetadata?.getDisplayName(uiCulture)
		let configuration = DocClaimsModelConfiguration(id: doc.id, createdAt: doc.createdAt, docType: doc.docType, displayName: displayName, display: docMetadata?.display, issuerDisplay: docMetadata?.issuerDisplay, credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier, validFrom: validFrom, validUntil: validUntil, statusIdentifier: statusIdentifier, credentialsUsageCounts: nil, credentialPolicy: docKeyInfo.credentialPolicy, secureAreaName: docKeyInfo.secureAreaName, modifiedAt: doc.modifiedAt, docClaims: docClaims, docDataFormat: .sdjwt, hashingAlg: recreatedClaims.hashingAlg)
		return DocClaimsModel(configuration: configuration)
	}

	public static func getHashingAlgorithm(doc: WalletStorage.Document) -> String? {
		guard doc.docDataFormat == .sdjwt else { return nil }
		guard let recreatedClaims = recreateSdJwtClaims(docData: doc.data) else { return nil }
		return recreatedClaims.hashingAlg
	}

	public static func getVctFromSdJwt(docData: Data) -> String? {
		guard let recreatedClaims = recreateSdJwtClaims(docData: docData) else { return nil }
		return recreatedClaims.json["vct"].stringValue
	}

	static func recreateSdJwtClaims(docData: Data) -> (json: JSON, hashingAlg: String)? {
		let parser = CompactParser()
		guard let serString = String(data: docData, encoding: .utf8) else { logger.error("Failed to convert document data to UTF8 string"); return nil}
		guard let sdJwt = try? parser.getSignedSdJwt(serialisedString: serString) else { logger.error("Failed to parse serialized SDJWT"); return nil }
		var recreatedClaims: JSON?; var hashingAlg: String?
		do {
			let result = try sdJwt.recreateClaims()
			let (_, payload, _) = extractJWTParts(sdJwt.jwt.compactSerialization)
			guard let paylodData = Data(base64URLEncoded: payload), let payload = try? JSON(data: paylodData) else { logger.error("Failed to base64url decode payload"); return nil }
			hashingAlg = try payload.extractDigestAlgorithm()
			recreatedClaims = resolveNestedSdClaims(result.recreatedClaims, disclosures: sdJwt.disclosures, hashingAlg: hashingAlg ?? "sha-256")
		} catch { logger.error("Failed to recreate claims from SDJWT: \(error)") }
		guard let recreatedClaims, let hashingAlg else { return nil }
		return (recreatedClaims, hashingAlg)
	}

	/// Recursively resolve any remaining `_sd` digest arrays in the JSON tree using the raw disclosures.
	static func resolveNestedSdClaims(_ json: JSON, disclosures: [String], hashingAlg: String) -> JSON {
		// Build a map from base64url-encoded hash → decoded disclosure JSON
		var hashToDisclosure: [String: JSON] = [:]
		for disclosure in disclosures {
			guard let hash = computeDisclosureHash(disclosure, alg: hashingAlg) else { continue }
			guard let decoded = Data(base64URLEncoded: disclosure), let dJson = try? JSON(data: decoded) else { continue }
			hashToDisclosure[hash] = dJson
		}
		return resolveNode(json, hashToDisclosure: hashToDisclosure, hashingAlg: hashingAlg)
	}

	private static func resolveNode(_ json: JSON, hashToDisclosure: [String: JSON], hashingAlg: String) -> JSON {
		switch json.type {
		case .dictionary:
			var dict = json.dictionaryValue
			// If this object has an _sd array, resolve the hashes into actual claims
			if let sdArray = dict["_sd"]?.array {
				for hashJson in sdArray {
					let hashStr = hashJson.stringValue
					if let disclosure = hashToDisclosure[hashStr], disclosure.arrayValue.count >= 3 {
						let claimName = disclosure[1].stringValue
						let claimValue = disclosure[2]
						dict[claimName] = claimValue
					}
				}
				dict.removeValue(forKey: "_sd")
			}
			dict.removeValue(forKey: "_sd_alg")
			// Recursively resolve children
			var result = JSON([:])
			for (key, value) in dict {
				result[key] = resolveNode(value, hashToDisclosure: hashToDisclosure, hashingAlg: hashingAlg)
			}
			return result
		case .array:
			let resolved = json.arrayValue.compactMap { element -> JSON? in
				// Selectively disclosable array elements use {"...": "<digest>"}.
				// If a matching disclosure exists, replace the element with its disclosed value.
				// If no matching disclosure exists, the element is undisclosed and must be omitted.
				if element.type == .dictionary, let dots = element["..."].string {
					guard let disclosure = hashToDisclosure[dots], disclosure.arrayValue.count >= 2 else {
						return nil
					}
					return resolveNode(disclosure[1], hashToDisclosure: hashToDisclosure, hashingAlg: hashingAlg)
				}
				return resolveNode(element, hashToDisclosure: hashToDisclosure, hashingAlg: hashingAlg)
			}
			return JSON(resolved)
		default:
			return json
		}
	}

	private static func computeDisclosureHash(_ disclosure: String, alg: String) -> String? {
		guard let data = disclosure.data(using: .ascii) else { return nil }
		let digest: Data
		switch alg {
		case "sha-256": digest = Data(SHA256.hash(data: data))
		case "sha-384": digest = Data(SHA384.hash(data: data))
		case "sha-512": digest = Data(SHA512.hash(data: data))
		default: digest = Data(SHA256.hash(data: data))
		}
		return digest.base64URLEncodedString()
	}

	static func extractJWTParts(_ jwt: String) -> (String, String, String) {
		let parts = jwt.components(separatedBy: ".")
		return (parts.count > 0 ? parts[0] : "", parts.count > 1 ? parts[1] : "" , parts.count > 2 ? parts[2] : "")
	}

	static func parseCnfBindingKeys(fromDocumentData documentData: Data) throws -> [ECPublicKey] {
		guard let serialized = String(data: documentData, encoding: .utf8) else {
			throw WalletError(description: "Failed to decode SD-JWT credential data", code: .issuanceRequestFailed)
		}
		return try parseCnfBindingKeys(fromSerializedCredential: serialized)
	}

	static func parseCnfBindingKeys(fromSerializedCredential serialized: String) throws -> [ECPublicKey] {
		let (_, payload, _) = extractJWTParts(serialized)
		guard let payloadData = Data(base64URLEncoded: payload) else {
			throw WalletError(description: "Failed to decode SD-JWT payload", code: .issuanceRequestFailed)
		}
		let payloadJson = try JSON(data: payloadData)
		guard payloadJson["cnf"].exists(), payloadJson["cnf"].type == .dictionary else {
			throw WalletError(description: "Issued SD-JWT is missing a valid cnf claim", code: .issuanceRequestFailed)
		}
		return try parseCnfBindingKeys(payloadJson["cnf"])
	}

	static func parseCnfBindingKeys(_ cnf: JSON) throws -> [ECPublicKey] {
		var jwks: [JSON] = []
		if cnf["jwk"].type == .dictionary {
			jwks.append(cnf["jwk"])
		} else if cnf["jwk"].type == .array {
			jwks.append(contentsOf: cnf["jwk"].arrayValue)
		}
		if cnf["jwks"]["keys"].type == .array {
			jwks.append(contentsOf: cnf["jwks"]["keys"].arrayValue)
		}
		guard !jwks.isEmpty else {
			throw WalletError(description: "Issued SD-JWT cnf claim does not contain JWK binding keys", code: .issuanceRequestFailed)
		}
		return try jwks.map { jwk in
			guard let kty = jwk["kty"].string, kty == "EC",
					let curveName = jwk["crv"].string,
					let curve = ECCurveType(rawValue: curveName),
					let x = jwk["x"].string,
					let y = jwk["y"].string else {
				throw WalletError(description: "Issued SD-JWT cnf JWK is missing required key material", code: .issuanceRequestFailed)
			}
			return ECPublicKey(crv: curve, x: x, y: y)
		}
	}
}
