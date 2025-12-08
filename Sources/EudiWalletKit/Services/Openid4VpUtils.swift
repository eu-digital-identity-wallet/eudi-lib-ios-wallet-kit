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

	/// Simplify the DCQL by filtering credential sets and credentials based on what's available in the queryable source
	/// - Parameter queryable: An instance conforming to DcqlQueryable protocol
	/// - Returns: A simplified DCQL with only matching credentials and credential sets, or nil if nothing matches
	func simplified(using queryable: DcqlQueryable) -> DCQL? {
		// Simplify individual credentials
		let simplifiedCredentials = credentials.compactMap { $0.simplified(using: queryable) }

		// Simplify credential sets if they exist
		let simplifiedCredentialSets = credentialSets?.compactMap { credSetQuery -> CredentialSetQuery? in
			credSetQuery.simplified(using: queryable, availableCredentials: simplifiedCredentials)
		}

		// If no credentials match and no credential sets match, return nil
		guard !simplifiedCredentials.isEmpty || (simplifiedCredentialSets?.isEmpty == false) else {
			return nil
		}

		// Create a new DCQL with simplified components
		return try? DCQL(
			credentials: simplifiedCredentials,
			credentialSets: simplifiedCredentialSets
		)
	}
}

extension CredentialSetQuery {
	/// Simplify the credential set query by filtering options based on available credentials
	/// - Parameters:
	///   - queryable: An instance conforming to DcqlQueryable protocol
	///   - availableCredentials: List of available (simplified) credentials
	/// - Returns: A simplified CredentialSetQuery with only valid options, or nil if no options are satisfiable
	func simplified(using queryable: DcqlQueryable, availableCredentials: [CredentialQuery]) -> CredentialSetQuery? {
		// Filter options to only include sets where all credential queries are available
		let simplifiedOptions = options.compactMap { credentialSet -> Set<QueryId>? in
			// Check if all query IDs in this set correspond to available credentials
			let allQueriesAvailable = credentialSet.allSatisfy { queryId in
				availableCredentials.contains { credential in
					credential.id == queryId
				}
			}

			return allQueriesAvailable ? credentialSet : nil
		}

		// If no options remain valid, return nil
		guard !simplifiedOptions.isEmpty else { return nil }

		// Create a new CredentialSetQuery with simplified options
		return try? CredentialSetQuery(
			options: simplifiedOptions,
			required: self.required
		)
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

extension CredentialQuery {
	/// Simplify the credential query by filtering claims and claim sets based on what's available in the queryable source
	/// - Parameter queryable: An instance conforming to DcqlQueryable protocol
	/// - Returns: A simplified CredentialQuery with only matching claims/claim sets, or nil if no credentials match
	func simplified(using queryable: DcqlQueryable) -> CredentialQuery? {
		guard let docType = self.docType else { return nil }

		// Check if any credentials match the docType and format
		var matchingCredentials = queryable.getCredential(docOrVctType: docType, docDataFormat: self.dataFormat)
		guard !matchingCredentials.isEmpty else { return nil }

		// Check if multiple credentials can satisfy this query
		if let multiple, !multiple { matchingCredentials = [matchingCredentials.first! ] }
		// If no claims or claimSets are specified, return the query as-is (request all claims)
		let hasClaims = claims != nil && !claims!.isEmpty
		let hasClaimSets = claimSets != nil && !claimSets!.isEmpty
		guard hasClaims || hasClaimSets else { return self }

		// Filter claims to only include those that exist in the queryable source
		var simplifiedClaims: [ClaimsQuery]? = nil
		if let claims = self.claims, !claims.isEmpty {
			simplifiedClaims = claims.compactMap { claimQuery -> ClaimsQuery? in
				// Check if any matching credential has this claim
				let hasMatchingClaim = matchingCredentials.contains { credId in
					// If values are specified, check for value match first (takes precedence)
					if let values = claimQuery.values, !values.isEmpty {
						return queryable.hasClaimWithValue(id: credId, claimPath: claimQuery.path, values: values)
					}

					// Otherwise, check for claim path existence
					return queryable.hasClaim(id: credId, claimPath: claimQuery.path)
				}

				return hasMatchingClaim ? claimQuery : nil
			}
		}

		// Filter claim sets to only include those where all referenced claims exist in the simplified claims array
		// Note: claim_sets MUST NOT be present if claims is absent (DCQL spec requirement)
		var simplifiedClaimSets: [Set<ClaimId>]? = nil
		if let claimSets = self.claimSets, !claimSets.isEmpty, let simplifiedClaims = simplifiedClaims, !simplifiedClaims.isEmpty {
			simplifiedClaimSets = claimSets.compactMap { claimSet -> Set<ClaimId>? in
				// Check if all claim IDs in the set reference claims that exist in the simplified claims array
				let allClaimsReferenced = claimSet.allSatisfy { claimId in
					simplifiedClaims.contains { claim in
						// Match claim ID - the claim must have an ID that matches the one in the set
						claim.id == claimId
					}
				}

				return allClaimsReferenced ? claimSet : nil
			}
		}

		// If no claims match, return nil (claim_sets cannot exist without claims)
		guard let simplifiedClaims = simplifiedClaims, !simplifiedClaims.isEmpty else { return nil }

		// Create a new CredentialQuery with the filtered claims and claim sets
		return try? CredentialQuery(
			id: self.id,
			format: self.format,
			meta: self.meta,
			claims: simplifiedClaims,
			claimSets: simplifiedClaimSets,
			multiple: self.multiple,
			trustedAuthorities: self.trustedAuthorities,
			requireCryptographicHolderBinding: self.requireCryptographicHolderBinding
		)
	}

	/// Construct the final list of claim paths for each credential identifier based on DCQL claim selection logic
	/// - Parameter queryable: An instance conforming to DcqlQueryable protocol
	/// - Returns: A dictionary mapping credential IDs to their claim paths, or nil if the query cannot be satisfied
	///
	/// Selection logic:
	/// - If only `claims` is present: return all claims that can be satisfied
	/// - If both `claims` and `claim_sets` are present: return the first satisfiable claim_set option
	///   (Wallet MUST NOT return any claims if no claim_set can be satisfied)
	func constructClaimPaths(using queryable: DcqlQueryable) -> [String: [ClaimPath]]? {
		guard let docType = self.docType else { return nil }

		// Get matching credentials
		var matchingCredentials = queryable.getCredential(docOrVctType: docType, docDataFormat: self.dataFormat)
		guard !matchingCredentials.isEmpty else { return nil }

		// Check if multiple credentials can satisfy this query
		if let multiple, !multiple { matchingCredentials = [matchingCredentials.first!] }

		// If no claims are specified, return empty paths (all claims requested)
		guard let claims = self.claims, !claims.isEmpty else {
			// No specific claims requested - return empty array for each credential
			return Dictionary(uniqueKeysWithValues: matchingCredentials.map { ($0, []) })
		}

		// Build a lookup map of claims by their ID
		let claimsById = Dictionary(uniqueKeysWithValues: claims.compactMap { claim -> (ClaimId, ClaimsQuery)? in
			guard let claimId = claim.id else { return nil }
			return (claimId, claim)
		})

		// Determine which claims to include based on claim_sets presence
		let selectedClaims: [ClaimsQuery]?

		if let claimSets = self.claimSets, !claimSets.isEmpty {
			// Both claims and claim_sets are present: find the first satisfiable option
			selectedClaims = claimSets.first { claimSet in
				// Check if all claims in this set can be satisfied
				claimSet.allSatisfy { claimId in
					guard let claim = claimsById[claimId] else { return false }
					return matchingCredentials.contains { credId in
						if let values = claim.values, !values.isEmpty {
							return queryable.hasClaimWithValue(id: credId, claimPath: claim.path, values: values)
						}
						return queryable.hasClaim(id: credId, claimPath: claim.path)
					}
				}
			}.map { claimSet in
				// Convert the satisfiable claim set to an array of ClaimsQuery
				claimSet.compactMap { claimsById[$0] }
			}

			// If no claim_set can be satisfied, return nil (per DCQL spec)
			guard selectedClaims != nil else { return nil }
		} else {
			// Only claims present: use all claims
			selectedClaims = claims
		}

		guard let selectedClaims = selectedClaims, !selectedClaims.isEmpty else { return nil }

		// Build the result: for each credential, collect the claim paths that can be satisfied
		var result: [String: [ClaimPath]] = [:]

		for credId in matchingCredentials {
			let satisfiablePaths = selectedClaims.compactMap { claim -> ClaimPath? in
				let canSatisfy: Bool
				if let values = claim.values, !values.isEmpty {
					canSatisfy = queryable.hasClaimWithValue(id: credId, claimPath: claim.path, values: values)
				} else {
					canSatisfy = queryable.hasClaim(id: credId, claimPath: claim.path)
				}
				return canSatisfy ? claim.path : nil
			}

			// Only include credentials that can satisfy at least one claim
			if !satisfiablePaths.isEmpty {
				result[credId] = satisfiablePaths
			}
		}

		return result.isEmpty ? nil : result
	}
}