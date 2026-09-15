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
import MdocDataTransfer18013
import struct OpenID4VP.DCQL
import struct eudi_lib_sdjwt_swift.SignedSDJWT

/// Builds TS10 presentation entries from requests and responses.
/// Records credential identifiers and claim paths without credential values or response tokens.
enum TransactionLogUtils {
	/// Creates a pending presentation entry with a new identifier, the current time and no claims.
	static func createEmptyPresentationLog() -> TransactionEntry {
		.presentation(.init(
			transactionIdentifier: UUID().uuidString,
			time: Date(),
			transactionResult: .notCompleted,
			listOfClaimsRequested: [],
			listOfClaimsPresented: []))
	}
	private static let defaultLang = "en"

	/// Parses requested claims from every DCQL credential and claim alternative, including unmatched types.
	/// When claims are omitted, expands the paths from all matching wallet credentials if available.
	static func parseRequestedClaims(_ dcql: DCQL, queryable: (any DcqlQueryable)? = nil) -> [ClaimInfo] {
		var result = [ClaimInfo]()
		for credential in dcql.credentials {
			let identifiers: [String]
			if let docType = credential.meta["doctype_value"].string {
				identifiers = [docType]
			} else {
				identifiers = credential.meta["vct_values"].arrayValue.compactMap { $0.string }
			}
			for identifier in identifiers {
				var paths = credential.claims?.map { $0.path.mdocClaimPath } ?? []
				if credential.claims?.isEmpty != false, let queryable {
					paths = queryable.getCredentials(docOrVctType: identifier, docDataFormat: credential.dataFormat).sorted().flatMap {
						queryable.getAllClaimPaths(id: $0).map { $0.mdocClaimPath }
					}
				}
				result.append(ClaimInfo(credentialIdentifier: identifier, claims: paths))
			}
		}
		return mergeClaims(result)
	}

	/// Parses requested mdoc claims as namespace and element paths, grouped by document type.
	static func parseRequestedClaims(_ request: DeviceRequest) -> [ClaimInfo] {
		mergeClaims(request.docRequests.map { document in
			let namespaces = document.itemsRequest.requestNameSpaces.nameSpaces
			let paths: [MdocDataModel18013.ClaimPath] = namespaces.keys.sorted().flatMap { namespace in
				namespaces[namespace]!.elementIdentifiers.sorted().map { name in
					.init([.claim(name: namespace), .claim(name: name)])
				}
			}
			return .init(credentialIdentifier: document.itemsRequest.docType, claims: paths)
		})
	}

	/// Parses request items into claim paths, grouped by credential type.
	/// Uses namespace and element names for mdoc, and typed claim-path segments for SD-JWT VC.
	/// Document identifiers fall back to the item keys; unspecified formats default to mdoc.
	static func parseCborClaims(_ items: RequestItems, idsToDocTypes: [String: String] = [:]) -> [ClaimInfo] {
		var result = [ClaimInfo]()
		for id in items.keys.sorted() {
			let identifier = idsToDocTypes[id] ?? id
			var paths = [MdocDataModel18013.ClaimPath]()
			for namespace in items[id]!.keys.sorted() {
				for item in items[id]![namespace]! {
					let elements: [MdocDataModel18013.ClaimPathElement]
					elements = [.claim(name: namespace), .claim(name: item.elementIdentifier)]
					paths.append(.init(elements))
				}
			}
			result.append(.init(credentialIdentifier: identifier, claims: paths))
		}
		return mergeClaims(result)
	}

	/// Parses the disclosed SD-JWT claim paths in description order, without their values.
	/// Returns no claims when disclosure paths are unavailable.
	/// - Throws: An error if the SD-JWT claims cannot be reconstructed.
	static func parsePresentedClaims(_ sdJwt: SignedSDJWT, docType: String) throws -> [ClaimInfo] {
		guard let disclosures = try sdJwt.recreateClaims().disclosuresPerClaimPath else { return [] }
		let paths = disclosures.keys.map { path in
			MdocDataModel18013.ClaimPath(path.value.map { element in
				switch element {
				case .claim(let name): return .claim(name: name)
				case .arrayElement(let index): return .arrayElement(index: index)
				case .allArrayElements: return .allArrayElements
				}
			})
		}.sorted { $0.description < $1.description }
		return [.init(credentialIdentifier: docType, claims: paths)]
	}

	/// Groups claims by credential identifier and removes duplicate paths.
	/// Sorts credentials by identifier and preserves the first occurrence of each path.
	static func mergeClaims(_ claims: [ClaimInfo]) -> [ClaimInfo] {
		var pathsByCredential = [String: [MdocDataModel18013.ClaimPath]]()
		for info in claims {
			var paths = pathsByCredential[info.credentialIdentifier] ?? []
			for path in info.claims where !paths.contains(path) { paths.append(path) }
			pathsByCredential[info.credentialIdentifier] = paths
		}
		return pathsByCredential.keys.sorted().map { .init(credentialIdentifier: $0, claims: pathsByCredential[$0]!) }
	}

	/// Adds requested claims and the relying party's registration details to a presentation entry.
	/// Falls back to the supplied name and identifier when registration details are unavailable.
	/// Preserves the transaction identifier and time, resets the result and presented claims,
	/// and leaves other transaction types unchanged.
	static func withRequest(_ claims: [ClaimInfo],
		policy: WrpRegistrationPolicy?, name: String?, identifier: String? = nil, transactionLog: inout TransactionEntry) {
		guard case let .presentation(previous) = transactionLog else { return }
		let dpa = policy?.supervisoryAuthority
		transactionLog = .presentation(.init(
			transactionIdentifier: previous.transactionIdentifier,
			time: previous.time,
			transactionResult: .notCompleted,
			listOfClaimsRequested: mergeClaims(claims),
			listOfClaimsPresented: [],
			interactingPartyName: (policy.flatMap { interactingPartyName($0) } ?? name).map { .init(lang: defaultLang, content: $0) },
			interactingPartyIdentifier: (policy?.sub ?? identifier).flatMap { toQualifiedIdentifier($0) },
			interactingPartyContact: policy.flatMap { interactingPartyContact($0) },
			isIntermediary: policy?.intermediary == nil ? nil : true,
			intermediaryIdentifier: policy?.intermediary?.identifier.flatMap { toQualifiedIdentifier($0) },
			intermediaryName: policy?.intermediary?.name.map { .init(lang: defaultLang, content: $0) },
			registrarURL: policy?.registryURI,
			purpose: policy?.purpose?.map { .init(lang: $0.lang, content: $0.value) },
			privacyPolicy: policy?.privacyPolicy.map { [.init(type: Policy.privacyPolicy, policyURI: $0)] },
			dpaName: dpa?.name.map { .init(lang: defaultLang, content: $0) },
			dpaContact: dpa.map { [$0.email, $0.phone, $0.uri].compactMap { $0 } }
		))
	}

	/// Returns the registered legal name, or the given and family names of a natural person.
	/// Falls back to the registration's display name when neither is available.
	static func interactingPartyName(_ policy: WrpRegistrationPolicy) -> String? {
		if let legalName = policy.subLn, !legalName.isEmpty { return legalName }
		let personalName = [policy.subGn, policy.subFn].compactMap { $0 }.joined(separator: " ")
		return personalName.isEmpty ? policy.name : personalName
	}

	/// Returns the registered country and contact URLs, or nil when none are available.
	static func interactingPartyContact(_ policy: WrpRegistrationPolicy) -> [String]? {
		let contact = [policy.country, policy.supportURI, policy.infoURI].compactMap { $0 }
		return contact.isEmpty ? nil : contact
	}

	/// Maps the issuer's registration entitlements to its TS10 interacting-party type.
	/// Uses the first recognized entitlement in PID, QEAA, public EAA and non-qualified EAA order.
	static func interactingPartyType(_ policy: WrpRegistrationPolicy?) -> String? {
		let types: [(String, IssuerProviderType)] = [
			(IssuerEntitlements.pid, .pidProvider),
			(IssuerEntitlements.qeaa, .qeaaProvider),
			(IssuerEntitlements.pubEaa, .pubEaaProvider),
			(IssuerEntitlements.nonQEaa, .nonQEaaProvider)
		]
		return types.first { entitlement, _ in
			policy?.entitlements?.contains(entitlement) == true
		}?.1.rawValue
	}

	/// Parses a an ETSI EN 319 412-1 semantic identifier.
	static func toQualifiedIdentifier(_ value: String) -> QualifiedIdentifier? {
       let prefix = String(value.prefix(3)).uppercased()
        let type: String

        switch prefix {
        case "LEI": type = QualifiedIdentifier.lei
        case "VAT": type = QualifiedIdentifier.vatin
        case "NTR": type = QualifiedIdentifier.euid
        case "EOR": type = QualifiedIdentifier.eori
        case "EXC": type = QualifiedIdentifier.excise
        default: return nil
        }
        guard let hyphenIndex = value.firstIndex(of: "-") else {
            return nil
        }
        let identifierValue = String(value[hyphenIndex...].dropFirst())
        guard !identifierValue.isEmpty else { return nil }
        return QualifiedIdentifier(type: type, value: identifierValue)
	}

	/// Sets the presentation result and optional reason of non-completion.
	/// Replaces presented claims when supplied; otherwise keeps the recorded claims.
	/// Preserves request and party details, and leaves other transaction types unchanged.
	static func withResult(_ result: TransactionResult,
		reason: String? = nil, presented: [ClaimInfo]? = nil, transactionLog: inout TransactionEntry) {
		guard case let .presentation(previous) = transactionLog else { return }
		transactionLog = .presentation(.init(
			transactionIdentifier: previous.transactionIdentifier,
			time: previous.time,
			transactionResult: result,
			reasonOfNoncompletion: reason,
			listOfClaimsRequested: previous.listOfClaimsRequested,
			listOfClaimsPresented: presented ?? previous.listOfClaimsPresented,
			interactingPartyType: previous.interactingPartyType,
			interactingPartyName: previous.interactingPartyName,
			interactingPartyIdentifier: previous.interactingPartyIdentifier,
			interactingPartyContact: previous.interactingPartyContact,
			isIntermediary: previous.isIntermediary,
			intermediaryIdentifier: previous.intermediaryIdentifier,
			intermediaryName: previous.intermediaryName,
			intermediaryContact: previous.intermediaryContact,
			registrarURL: previous.registrarURL,
			purpose: previous.purpose,
			privacyPolicy: previous.privacyPolicy,
			dpaName: previous.dpaName,
			dpaCountry: previous.dpaCountry,
			dpaContact: previous.dpaContact))
	}
}
