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
import OpenID4VP
import enum OpenID4VP.ClaimPathElement
import struct OpenID4VP.ClaimPath
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

protocol DcqlQueryable {
	/// retrieve credential identifiers matching docType and dataFormat
	func getCredential(docOrVctType: String, docDataFormat: DocDataFormat) -> [String]
	/// retrieve all claim paths for a given credential identifier
	func getAllClaimPaths(id: String) -> [ClaimPath]
	/// check if a claim exists for a given credential identifier and claim path
	func hasClaim(id: String, claimPath: ClaimPath) -> Bool
	/// check if a claim exists for a given credential identifier and claim path and value
	func hasClaimWithValue(id: String, claimPath: ClaimPath, values: [String]) -> Bool
}

extension Openid4VpUtils {
	/// Resolves a DCQL query against available credentials in the wallet
	///
	/// This function evaluates a DCQL (Digital Credentials Query Language) query to determine if the wallet
	/// can satisfy the request. It returns a mapping of credential identifiers to the claim paths that should
	/// be disclosed, or nil if the query cannot be satisfied.
	///
	/// The resolution process follows the DCQL specification from OpenID4VP 1.0:
	/// - Evaluates credential queries to find matching credentials by format and metadata
	/// - Processes claim queries with support for claim_sets (alternative claim combinations)
	/// - Handles credential_sets for requesting multiple credentials or alternatives
	/// - Supports optional vs required credential sets
	/// - Validates claim value matching when specified
	///
	/// - Parameters:
	///   - dcql: The DCQL query to resolve
	///   - queryable: An object conforming to DcqlQueryable that provides access to wallet credentials
	/// - Returns: A dictionary mapping matched credential IDs to arrays of ClaimPath objects representing
	///            the claims to disclose, or nil if the query cannot be satisfied
	///
	/// - Note: According to the spec:
	///   - If claims is absent, only mandatory claims are returned
	///   - If claims is present but claim_sets is absent, all listed claims are requested
	///   - If both claims and claim_sets are present, one combination from claim_sets is selected
	///   - The wallet returns the first claim_sets option it can satisfy (Verifier's preference order)
	///   - If the wallet cannot deliver all non-optional credentials, it returns nil
	static func resolveDcql(_ dcql: DCQL, queryable: DcqlQueryable) -> [String: [ClaimPath]]? {
		var result: [String: [ClaimPath]] = [:]
		var credentialQueryResults: [QueryId: (matchedCredId: String, claimPaths: [ClaimPath])] = [:]

		// Step 1: Process individual credential queries
		for credQuery in dcql.credentials {
			guard let docType = credQuery.docType else { continue }
			let format = credQuery.dataFormat

			// Find matching credentials
			let matchingCredIds = queryable.getCredential(docOrVctType: docType, docDataFormat: format)
			guard !matchingCredIds.isEmpty else {
				// No matching credential found - this query cannot be satisfied
				credentialQueryResults.removeValue(forKey: credQuery.id)
				continue
			}

			// Try to find a credential that satisfies the claim requirements
			var foundMatch = false
			for credId in matchingCredIds {
				if let claimPaths = resolveClaimsForCredential(credQuery: credQuery, credId: credId, queryable: queryable) {
					credentialQueryResults[credQuery.id] = (credId, claimPaths)
					foundMatch = true
					break
				}
			}

			if !foundMatch {
				credentialQueryResults.removeValue(forKey: credQuery.id)
			}
		}

		// Step 2: Handle credential_sets if present
		if let credentialSets = dcql.credentialSets {
			// When credential_sets are present, we need to satisfy at least all required sets
			// First pass: check if all required sets can be satisfied
			for credSet in credentialSets where credSet.required {
				var setIsSatisfied = false

				for option in credSet.options {
					let allSatisfied = option.allSatisfy { queryId in
						credentialQueryResults[queryId] != nil
					}
					if allSatisfied {
						setIsSatisfied = true
						break
					}
				}

				// If a required set cannot be satisfied, fail immediately
				if !setIsSatisfied {
					return nil
				}
			}

			// Second pass: add credentials from satisfied options (both required and optional)
			for credSet in credentialSets {
				for option in credSet.options {
					let allSatisfied = option.allSatisfy { queryId in
						credentialQueryResults[queryId] != nil
					}

					if allSatisfied {
						// Add the credentials from this option to the result
						for queryId in option {
							if let match = credentialQueryResults[queryId] {
								// If the credential ID already exists, merge claim paths
								if let existingPaths = result[match.matchedCredId] {
									// Merge and deduplicate claim paths
									let mergedPaths = existingPaths + match.claimPaths
									let uniquePaths = Array(Set(mergedPaths.map(\.value))).compactMap { pathValue in
										mergedPaths.first { $0.value == pathValue }
									}
									result[match.matchedCredId] = uniquePaths
								} else {
									result[match.matchedCredId] = match.claimPaths
								}
							}
						}
						break // Take the first satisfiable option for this credential_set
					}
				}
			}
		} else {
			// No credential_sets: all credential queries must be satisfied
			for (_, match) in credentialQueryResults {
				result[match.matchedCredId] = match.claimPaths
			}
		}

		return result.isEmpty ? nil : result
	}

	/// Resolves claims for a specific credential query and credential
	private static func resolveClaimsForCredential(credQuery: CredentialQuery, credId: String, queryable: DcqlQueryable) -> [ClaimPath]? {
		// If no claims specified, return empty array (only mandatory claims)
		guard let claims = credQuery.claims, !claims.isEmpty else {
			return []
		}
		// If claim_sets is present, try to satisfy one of the claim set options
		if let claimSets = credQuery.claimSets, !claimSets.isEmpty {
			// Try each claim set option in order (first is most preferred)
			for claimSetOption in claimSets {
				var selectedPaths: [ClaimPath] = []
				var allClaimsAvailable = true

				for claimId in claimSetOption {
					// Find the claim with this ID
					guard let claim = claims.first(where: { $0.id?.id == claimId.id }) else {
						allClaimsAvailable = false
						break
					}
					// Check value matching if specified
					if let values = claim.values, !values.isEmpty {
						if !queryable.hasClaimWithValue(id: credId, claimPath: claim.path, values: values) {
							allClaimsAvailable = false
							break
						}
					} else if !queryable.hasClaim(id: credId, claimPath: claim.path) {
						allClaimsAvailable = false
						break
					}
					selectedPaths.append(claim.path)
				}

				if allClaimsAvailable {
					// This claim set option can be satisfied
					return selectedPaths
				}
			}

			// No claim set option could be satisfied
			return nil
		} else {
			// No claim_sets: all claims must be available
			var selectedPaths: [ClaimPath] = []

			for claim in claims {
				// Check if the credential has this claim
				if let values = claim.values, !values.isEmpty {
					if !queryable.hasClaimWithValue(id: credId, claimPath: claim.path, values: values) {
						return nil
					}
				} else if !queryable.hasClaim(id: credId, claimPath: claim.path) {
					return nil
				}
				selectedPaths.append(claim.path)
			}
			return selectedPaths
		}
	}
}
