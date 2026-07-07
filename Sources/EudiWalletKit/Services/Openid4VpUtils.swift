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
import OrderedCollections
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
import struct WalletStorage.Document

class OpenId4VpUtils {
	//  example path: "$['eu.europa.ec.eudiw.pid.1']['family_name']"
	static let pathNsItemRx = try! NSRegularExpression(pattern: #"\$\['([^']+)'\]\['([^']+)'\]"#, options: .caseInsensitive)
	// example path: $.given_name_national_character
	static let pathItemRx: NSRegularExpression = try! NSRegularExpression(pattern: #"\$\.(.+)"#, options: .caseInsensitive)

	/// Generate the `SessionTranscript` CBOR where the presentation request is invoked using redirects.
	/// - Parameters:
	///   - clientId: The `client_id` request parameter. If applicable, this includes the Client Identifier Prefix.
	///   - responseUri: Either the `redirect_uri` or `response_uri` request parameter, depending on which is present, as determined by the Response Mode.
	///   - nonce: The value of the `nonce` request parameter.
	///   - jwkThumbprint: If the response is encrypted, e.g., using `direct_post.jwt`, this element must be the JWK SHA-256 Thumbprint of the Verifier's public key used to encrypt the response. Otherwise `nil`.
	/// - Returns: A CBOR representation of the OpenID4VPHandover structure.
	/// - Remark: See [Handover and SessionTranscript Definitions](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-handover-and-sessiontranscript).
	static func generateOpenId4VpHandover(clientId: String,	responseUri: String, nonce: String, jwkThumbprint: [UInt8]? = nil) -> CBOR {
		let jwkThumbprintCbor: CBOR = jwkThumbprint != nil ? .byteString(jwkThumbprint!) : .null
		let openID4VPHandoverInfoToHash = CBOR.array([.utf8String(clientId), .utf8String(nonce), jwkThumbprintCbor, .utf8String(responseUri)])
		let	openID4VPHandoverInfo = [UInt8](SHA256.hash(data: openID4VPHandoverInfoToHash.asData()))
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
	static func parseDcqlFormats(_ dcql: DCQL, idsToDocTypes: [Document.ID: DocType], logger: Logger? = nil) throws -> (formatsRequested: [DocType: DocDataFormat], inputDescriptorMap: [DocType: String], zkSpecsRequested: [DocType: [ZkSystemSpec]]?) {
		var inputDescriptorMap = [DocType: String]()
		var formatsRequested = [DocType: DocDataFormat]()
		var zkSpecsRequested: [DocType: [ZkSystemSpec]]?
		for credQuery in dcql.credentials {
			let formatRequested: DocDataFormat = credQuery.dataFormat
			guard let docType = credQuery.docType else { continue }
			if !idsToDocTypes.values.contains(docType) {logger?.warning("Document type \(docType) not in supported document types \(idsToDocTypes.values)")}
			inputDescriptorMap[docType] = credQuery.id.value; formatsRequested[docType] = formatRequested
			if let zkSpecs = credQuery.zkSpecs {
				if zkSpecsRequested == nil { zkSpecsRequested = [:] }
				zkSpecsRequested![docType] = zkSpecs
			}
		}
		return (formatsRequested, inputDescriptorMap, zkSpecsRequested)
	}
	
	static func makeCredentialMap(idsToDocTypes: [Document.ID: DocType], formatsRequested: [DocType: DocDataFormat]) -> [Document.ID: (DocType, DocDataFormat)] {
		var credentialMap = [Document.ID: (DocType, DocDataFormat)]()
		for (docId, docType) in idsToDocTypes {
			if let format = formatsRequested[docType] {
				credentialMap[docId] = (docType, format)
			}
		}
		return credentialMap
	}
	
	static func getRequestItems(_ credentialSetOptions: CredentialSelectionSetOptions, idsToDocTypes: [Document.ID: DocType], formatsRequested: [DocType: DocDataFormat]) -> [(String, RequestItems)] {
		var requestItemsArray = [(String, RequestItems)]()
		for (requestName, credentialSet) in credentialSetOptions {
			var requestItems = RequestItems()
			for credentialSelectionSet in credentialSet {
				let id = credentialSelectionSet.credentialId
				guard let docType = idsToDocTypes[id], let formatRequested = formatsRequested[docType] else { continue }
				var nsItems: [String: [RequestItem]] = [:]
				for claim in credentialSelectionSet.claimQueries {
					guard let pair = Self.parseClaim(claim, formatRequested) else { continue }
					if !nsItems[pair.0, default: []].contains(pair.1) { nsItems[pair.0, default: []].append(pair.1) }
				}
				requestItems[id] = nsItems
			}
			requestItemsArray.append((requestName, requestItems))
		}
		return requestItemsArray
	}


	static func getTransactionDataRequested(_ credentialSetOptions: CredentialSelectionSetOptions, transactionDataList: [TransactionData]) throws -> [(String, RequestTransactionData)] {
		var result = [(String, RequestTransactionData)]()
		for (requestName, credentialSet) in credentialSetOptions {
			var requestTransactionData: RequestTransactionData = [:]
			for transactionData in transactionDataList {
				let type = try transactionData.type()
				let credentialIds = try transactionData.credentialIds()
				let parameters = try transactionData.decode()
				for credentialId in credentialIds {
					if let document = credentialSet.first(
						where: { value in value.queryId.value == credentialId.value
						}) {
						if (requestTransactionData[document.credentialId] == nil) {
							requestTransactionData[document.credentialId] = [:]
						}
						requestTransactionData[document.credentialId]![type.value] = parameters
						break
					} else {
						throw WalletError(description: "Failed to find document for transaction data \(type) with credential id \(credentialId.value)")
					}
				}
			}
			result.append((requestName, requestTransactionData))
		}
		return result
	}
	
	static func getVerifierInfoRequested(_ credentialSetOptions: CredentialSelectionSetOptions, verifierInfoList: [VerifierInfo]) -> [(String, RequestVerifierInfo)] {
		var result = [(String, RequestVerifierInfo)]()
		for (requestName, credentialSet) in credentialSetOptions {
			var requestVerifierInfo: RequestVerifierInfo = [:]
			for verifierInfo in verifierInfoList {
				var documentIds = [Document.ID]()
				if (verifierInfo.credentialIds == nil) {
					documentIds = credentialSet.map({ $0.credentialId })
				} else {
					for credentialId in verifierInfo.credentialIds! {
						if let document = credentialSet.first(
							where: { value in value.queryId.value == credentialId.value
						 }) {
							documentIds.append(document.credentialId)
						}
					}
				}
				for documentId in documentIds {
					if (requestVerifierInfo[documentId] == nil) {
						requestVerifierInfo[documentId] = [:]
					}
					requestVerifierInfo[documentId]![verifierInfo.format] = verifierInfo.data
				}
			}
			result.append((requestName, requestVerifierInfo))
		}
		return result
	}

	static func makeCborClaimData(
		from docsCbor: [Document.ID: IssuerSigned]?,
		claimPaths: inout [Document.ID: [ClaimPath]],
		claimValues: inout [Document.ID: [ClaimPath: [String]]]
	) {
		var paths = [ClaimPath](); var values = [ClaimPath: [String]]()

		for (docId, issuerSigned) in docsCbor ?? [:] {
			paths.removeAll(); values.removeAll()
			guard let isNs = issuerSigned.issuerNameSpaces else { continue }
			for (ns, items) in isNs.nameSpaces {
				for item in items {
					paths.append(ClaimPath([.claim(name: String(ns)), .claim(name: item.elementIdentifier)]))
					values[paths.last!] = [item.description]
				}
			}
			claimPaths[docId] = paths
			claimValues[docId] = values
		}
	}

	static func makeSdJwtClaimData(
		from docsSdJwt: [Document.ID: SignedSDJWT]?,
		claimPaths: inout [Document.ID: [ClaimPath]],
		claimValues: inout [Document.ID: [ClaimPath: [String]]]
	) {
		var paths = [ClaimPath](); var values = [ClaimPath: [String]]()

		for (docId, sdjwt) in docsSdJwt ?? [:] {
			guard let allPathsDict = (try? sdjwt.recreateClaims())?.disclosuresPerClaimPath else { continue }
			paths.removeAll(); values.removeAll()
			for (p, disclosures) in allPathsDict {
				let mappedElements = p.value.map { element in
					if case .claim(let name) = element { return ClaimPathElement.claim(name: name) }
					if case .arrayElement(let index) = element { return ClaimPathElement.arrayElement(index: index) }
					return ClaimPathElement.allArrayElements
				}
				let path = ClaimPath(mappedElements)
				paths.append(path)
				values[path] = disclosures
			}
			claimPaths[docId] = paths
			claimValues[docId] = values
		}
	}

	/// parse claim-query and return (namespace, itemIdentifier) pair
	static func parseClaim(_ claim: ClaimsQuery, _ docDataFormat: DocDataFormat) -> (String, RequestItem)? {
		let elementPath = claim.path.value.map(\.claimName)
		if docDataFormat == .cbor {
			guard elementPath.count >= 2 else { return nil }
			let ns = elementPath.first!
			let itemIdentifier = elementPath[1]
			return (ns, RequestItem(elementPath: [itemIdentifier], intentToRetain: claim.intentToRetain, isOptional: false))
		} else if docDataFormat == .sdjwt {
			return ("", RequestItem(elementPath: elementPath, intentToRetain: false, isOptional: false))
		}
		return nil
	}

	static func getSdJwtPresentation(_ sdJwt: SignedSDJWT, hashingAlg: HashingAlgorithm, signer: SecureAreaSigner, signAlg: JSONWebAlgorithms.SigningAlgorithm, requestItems: [RequestItem], nonce: String, aud: String, transactionData: [TransactionData]?) async throws -> SignedSDJWT? {
		guard let allPathsDict = (try sdJwt.recreateClaims()).disclosuresPerClaimPath else { throw WalletError(description: "No disclosures found") }
		let allPaths = Array(allPathsDict.keys)
		let query = Set(allPaths.filter { path in requestItems.contains(where: { r in r.claimPath == path }) })
		for q in query { print(q.value.map(\.description) ) }
		let presentedSdJwt = try sdJwt.present(query: query)
		guard let presentedSdJwt else { return nil }
		let digestCreator = DigestCreator(hashingAlgorithm: hashingAlg)
		guard let sdHash = digestCreator.hashAndBase64Encode(input: CompactSerialiser(signedSDJWT: presentedSdJwt).serialised) else { return nil }
		let issuedAtTimestamp = Int(Date().timeIntervalSince1970.rounded())
		var payload = [Keys.nonce.rawValue: nonce, Keys.aud.rawValue: aud, Keys.iat.rawValue: issuedAtTimestamp, Keys.sdHash.rawValue: sdHash] as [String : Any]
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
		OpenId4VpUtils.vctToDocType(s1).hasPrefix(OpenId4VpUtils.vctToDocType(s2)) || OpenId4VpUtils.vctToDocType(s2).hasPrefix(OpenId4VpUtils.vctToDocType(s1))
	}
}

extension ClaimPathElement {
	public var claimName: String {
		if case .claim(let name) = self { name } else if case .arrayElement(let index) = self { String(index) } else { "" }
	}
}

extension CredentialQuery {
	public var docType: String? {
		let mdocTypeValue = meta.dictionaryObject?["doctype_value"]
		let vctValues = meta.dictionaryObject?["vct_values"]
		let metaDocType = mdocTypeValue ?? vctValues ?? meta.dictionaryObject?.first?.value
		let docType = metaDocType as? String ?? (metaDocType as? [String])?.first
		return docType
	}

	// https://developers.google.com/wallet/identity/verify/accepting-ids-from-wallet-online#zkp
	public var zkSpecs: [ZkSystemSpec]? {
		let zk_system_type = meta["zk_system_type"]
		guard zk_system_type.type == .array, let zkArray = zk_system_type.array else { return nil }
		return zkArray.compactMap { try? ZkSystemSpec(jsonObject:$0) }
	}

	public var dataFormat: DocDataFormat {
		format.format == "mso_mdoc" || format.format == "mso_mdoc_zk" ? .cbor : .sdjwt
	}
}

extension ClaimPath {
 	public func contains2(_ that: ClaimPath) -> Bool { zip(self.value, that.value).allSatisfy { (selfElement, thatElement) in selfElement.contains(thatElement) } }
}

extension DCQL {
	public func findQuery(id: String) -> CredentialQuery? {
		credentials.first { $0.id.value == id }
	}
}

extension CredentialSelectionSet {
	/// Merges claims if the credential already exists in the set, otherwise appends
	mutating func mergeOrAppend(_ sel: CredentialSelection) {
		if let existing = first(where: { $0.credentialId == sel.credentialId }) {
			let mergedPaths = existing.claimQueries + sel.claimQueries
			let uniquePaths = Array(Set(mergedPaths.map(\.path.value))).compactMap { p in mergedPaths.first { $0.path.value == p } }
			remove(existing)
			append(CredentialSelection(credentialId: sel.credentialId, docType: sel.docType, queryId: existing.queryId, optionId: existing.optionId, claimQueries: uniquePaths))
		} else {
			append(sel)
		}
	}
}

extension OpenId4VpUtils {
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
	///            the claims to disclose
	/// - Throws: WalletError if the query cannot be satisfied, with details about the first missing claim
	static func resolveDcql(_ dcql: DCQL, queryable: DcqlQueryable, docTypeDisplayNames: [DocType: String] = [:]) throws -> CredentialSelectionSetOptions {
		var resultDict: CredentialSelectionSetOptions = [:]
		var lastError: WalletError?
		var credentialQueryResults: OrderedDictionary<QueryId, [CredentialSelection]> = [:]
		// Step 1: Process individual credential queries
		for credQuery in dcql.credentials {
			guard let docType = credQuery.docType else { throw WalletError(description: "Credential query \(credQuery.id.value) does not have a doc type") }
			let format = credQuery.dataFormat
			let isMultiple = credQuery.multiple == true
			// Find matching credentials
			let matchingCredIds = queryable.getCredentials(docOrVctType: docType, docDataFormat: format)
			let docTypeDisplayName = docTypeDisplayNames[docType] ?? docType
			if matchingCredIds.isEmpty, dcql.credentialSets == nil { throw WalletError(description: "Credential of type \(docTypeDisplayName) cannot be found.", code: .credentialNotFound, context: ["docType": docType]) }
			// Try to find credentials that satisfy the claim requirements
			for (credIndex, credId) in matchingCredIds.enumerated() {
				do {
					let optionId = !isMultiple ? "\(credQuery.id.value)-\(credIndex)" : credQuery.id.value
					let claimPaths = try resolveClaimsForCredential(credQuery: credQuery, credId: credId, queryable: queryable)
					credentialQueryResults[credQuery.id, default: []].append(CredentialSelection(credentialId: credId, docType: docType, queryId: credQuery.id, optionId: optionId, claimQueries: claimPaths))
					//if !isMultiple { break } // for non-multiple queries, stop at first match
				} catch {
					lastError = error
					logger.warning("Credential \(credId) does not satisfy query \(credQuery.id.value): \(error.localizedDescription)")
					// continue trying other credentials that match the docType
				}
			}
			if credentialQueryResults[credQuery.id]?.isEmpty != false, dcql.credentialSets == nil {
   			 throw lastError ?? WalletError(description: "No credential satisfies query \(credQuery.id.value)", code: .dcqlQueryNotSatisfied)
			}
		}
		// Step 2: Handle credential_sets if present
		if let credentialSets = dcql.credentialSets {
			// For each credential set, collect satisfiable options expanded by credential alternatives
			let setsWithOptions: [(isRequired: Bool, options: [(String, CredentialSelectionSet)])] = credentialSets.map { credSet in
				let isSetRequired = credSet.required ?? CredentialSetQuery.defaultRequiredValue
				let setOptions: [(String, CredentialSelectionSet)] = credSet.options.flatMap { option -> [(String, CredentialSelectionSet)] in
					let optionSatisfied = option.allSatisfy { queryId in credentialQueryResults[queryId]?.isEmpty == false }
					guard optionSatisfied else { return [] }
					// For each queryId in the option, get match groups (bundled for multiple, individual otherwise)
					let matchGroups: [[(String, [CredentialSelection])]] = option.map { queryId in
						let matches = credentialQueryResults[queryId] ?? []
						let isMultiple = dcql.findQuery(id: queryId.value)?.multiple == true
						if isMultiple {
							// Bundle all matches together as one group
							return [(matches.first?.optionId ?? queryId.value, matches)]
						} else {
							// Each match is a separate alternative
							return matches.map { ($0.optionId, [$0]) }
						}
					}
					// Cartesian product across match groups
					let combinations = matchGroups.reduce([([String](), [CredentialSelection]())]) { acc, groups in
						acc.flatMap { (keys, sels) in
							groups.map { (key, groupSels) in (keys + [key], sels + groupSels) }
						}
					}
					return combinations.map { (keys, sels) in
						let optionKey = keys.joined(separator: "+")
						let selections = sels.reduce(into: CredentialSelectionSet()) { set, sel in
							set.mergeOrAppend(sel)
						}
						return (optionKey, selections)
					}
				}
				return (isSetRequired, setOptions)
			}
			let requiredSetsOptions = setsWithOptions.filter(\.isRequired).map(\.options)
			let optionalSetsOptions = setsWithOptions.filter { !$0.isRequired && !$0.options.isEmpty }.map(\.options)
			// Verify all required sets are satisfiable
			if requiredSetsOptions.contains(where: \.isEmpty) {
				throw WalletError(description: "Required credential_set cannot be satisfied", code: .credentialSetNotSatisfied)
			}
			// Cartesian product across all required sets
			let requiredCombinations = requiredSetsOptions.reduce([(String, CredentialSelectionSet)]()) { acc, setOptions in
				if acc.isEmpty { return setOptions }
				return acc.flatMap { (existingKey, existingSet) in
					setOptions.map { (optKey, optSet) in
						let combinedKey = existingKey.isEmpty ? optKey : "\(existingKey)|\(optKey)"
						let combinedSet = optSet.reduce(into: existingSet) { set, sel in
							set.mergeOrAppend(sel)
						}
						return (combinedKey, combinedSet)
					}
				}
			}
			// Expand with optional sets (include variants with and without each optional)
			let combinations = optionalSetsOptions.reduce(requiredCombinations) { acc, optSetOptions in
				acc.flatMap { (existingKey, existingSet) in
					// Keep without optional + add each optional variant
					[(existingKey, existingSet)] + optSetOptions.map { (optKey, optSet) in
						let combinedKey = existingKey.isEmpty ? optKey : "\(existingKey)|\(optKey)"
						let combinedSet = optSet.reduce(into: existingSet) { set, sel in
							set.mergeOrAppend(sel)
						}
						return (combinedKey, combinedSet)
					}
				}
			}
			for (key, set) in combinations {
				resultDict[key] = set
			}
		} else {
			// No credential_sets: Cartesian product across credential query results
			// For `multiple` queries, all matches are bundled together; otherwise each match is a separate alternative
			let matchGroups: [(String, [(String, [CredentialSelection])])] = credentialQueryResults.map { (queryId, matches) in
				let isMultiple = dcql.findQuery(id: queryId.value)?.multiple == true
				if isMultiple {
					// All matches bundled as one group
					return (queryId.value, [(matches.first?.optionId ?? queryId.value, matches)])
				} else {
					// Each match is a separate alternative
					return (queryId.value, matches.map { ($0.optionId, [$0]) })
				}
			}

			let combinations = matchGroups.reduce([([String](), [CredentialSelection]())]) { acc, entry in
				let (_, groups) = entry
				return acc.flatMap { (keys, sels) in
					groups.map { (key, groupSels) in (keys + [key], sels + groupSels) }
				}
			}

			for (keys, sels) in combinations {
				let optionKey = keys.joined(separator: "|")
				let selectionSet = sels.reduce(into: CredentialSelectionSet()) { set, sel in
					set.mergeOrAppend(sel)
				}
				resultDict[optionKey] = selectionSet
			}
		}
		if resultDict.isEmpty {
			let notFoundCred = dcql.credentials.first { c in credentialQueryResults[c.id]?.isEmpty != false }
			if let notFoundCred {logger.warning("No credential found matching docType: \(notFoundCred.docType ?? "") with format: \(notFoundCred.format)")}
			throw lastError ?? WalletError(description: "DCQL query could not be satisfied", code: .dcqlQueryNotSatisfied)
		}
		return resultDict
	}

	/// Resolves claims for a specific credential query and credential
	/// - Throws: WalletError if claims cannot be satisfied, with details about the first missing claim
	private static func resolveClaimsForCredential(credQuery: CredentialQuery, credId: String, queryable: DcqlQueryable) throws(WalletError) -> [ClaimsQuery] {
		// If no claims specified, return empty array (only mandatory claims)
		guard let claims = credQuery.claims, !claims.isEmpty else {
			return []
		}
		// If claim_sets is present, try to satisfy one of the claim set options
		if let claimSets = credQuery.claimSets, !claimSets.isEmpty {
			// Try each claim set option in order, all of the option claims must be satisfied
			var firstMissingClaimInOption: ClaimPath?
			for claimSetOption in claimSets {
				var selectedPaths: [ClaimsQuery] = []
				firstMissingClaimInOption = nil
				for claimId in claimSetOption {
					// Find the claim with this ID
					guard let claim = claims.first(where: { $0.id?.id == claimId.id }) else {
						firstMissingClaimInOption = ClaimPath([.claim(name: "unknown_claim_\(claimId.id)")])
						break // skip remaining claims in this option
					}
					// Check value matching if specified
					if let values = claim.values, !values.isEmpty {
						if !queryable.hasClaimWithValue(id: credId, claimPath: claim.path, values: values) {
							firstMissingClaimInOption = claim.path
							break // skip remaining claims in this option
						}
					} else if !queryable.hasClaim(id: credId, claimPath: claim.path) {
						firstMissingClaimInOption = claim.path
						if firstMissingClaimInOption == nil {firstMissingClaimInOption = claim.path}
						break // skip remaining claims in this option
					}
					selectedPaths.append(claim)
				} // next claimId
				if firstMissingClaimInOption == nil {
					// This claim set option can be satisfied
					return selectedPaths
				}
			} // next claimSetOption
			// No claim set option could be satisfied
			let claimPathStr = firstMissingClaimInOption?.value.map(\.claimName).joined(separator: "/") ?? "unknown"
			throw WalletError(description: "No claim_set option satisfied. First missing claim: \(claimPathStr)", code: .claimSetNotSatisfied, context: ["claimPath": claimPathStr])
		} else {
			// No claim_sets: all claims must be available
			var selectedPaths: [ClaimsQuery] = []
			for claim in claims {
				// Check if the credential has this claim
				if let values = claim.values, !values.isEmpty {
					if !queryable.hasClaimWithValue(id: credId, claimPath: claim.path, values: values) {
						let claimPathStr = claim.path.value.map(\.claimName).joined(separator: "/")
						throw WalletError(description: "Claim value mismatch for: \(claimPathStr)", code: .claimValueMismatch, context: ["claimPath": claimPathStr])
					}
				} else if !queryable.hasClaim(id: credId, claimPath: claim.path) {
					let claimPathStr = claim.path.value.map(\.claimName).joined(separator: "/")
					throw WalletError(description: "Claim not found: \(claimPathStr)", code: .claimNotFound, context: ["claimPath": claimPathStr])
				}
				selectedPaths.append(claim)
			}
			return selectedPaths
		}
	}
}
