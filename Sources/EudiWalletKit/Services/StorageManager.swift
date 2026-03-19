/*
 Copyright (c) 2023 European Commission

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
import SwiftCBOR
import MdocDataModel18013
import WalletStorage
import Logging
import CryptoKit
import eudi_lib_sdjwt_swift
import SwiftyJSON
import OpenID4VCI

/// Storage manager. Provides services and view models
public final class StorageManager: ObservableObject, @unchecked Sendable {
	/// A static constant array containing known document types.
	/// This array includes document types from `EuPidModel` and `IsoMdlModel`.
	/// - Note: The document types included are `euPidDocType` and `isoDocType`.
	public static let knownDocTypes = [EuPidModel.euPidDocType, IsoMdlModel.isoDocType]
	/// A published property that holds an array of decoded documents conforming to the `DocClaimsModel` protocol.
	/// - Note: The `@Published` property wrapper is used to allow SwiftUI views to automatically update when the value changes.
	@Published public private(set) var docModels: [DocClaimsModel] = []
	/// - Note: This property is used to store documents that are deferred for later processing.
	@Published public private(set) var deferredDocuments: [WalletStorage.Document] = []
	/// A published property that holds an array of pending documents.
	@Published public private(set) var pendingDocuments: [WalletStorage.Document] = []
	var storageService: any DataStorageService
	/// Whether wallet currently has loaded data
	@Published public private(set) var hasData: Bool = false
	/// Count of documents loaded in the wallet
	@Published public private(set) var docCount: Int = 0
	/// Error object with localized message
	@Published public var uiError: WalletError?
	var modelFactory: (any DocClaimsDecodableFactory)?

	public init(storageService: any DataStorageService, modelFactory: (any DocClaimsDecodableFactory)? = nil) {
		self.storageService = storageService
		self.modelFactory = modelFactory
	}

	func refreshPublishedVars() async {
		await MainActor.run {
			hasData = !docModels.isEmpty || !deferredDocuments.isEmpty
			docCount = docModels.count
		}
	}

	/// Refreshes the document models with the specified status.
	///
	/// - Parameters:
	///   - docs: An array of `WalletStorage.Document` objects to be refreshed.
	///   - docStatus: The status of the documents.
	private func refreshDocModels(_ docs: [WalletStorage.Document], uiCulture: String?, docStatus: WalletStorage.DocumentStatus) async {
		switch docStatus {
		case .issued:
			let models = await docs.asyncCompactMap { d -> DocClaimsModel? in
				let mdoc = Self.toClaimsModel(doc:d, uiCulture: uiCulture, modelFactory: modelFactory)
				if let mdoc { mdoc.credentialsUsageCounts = try? await getCredentialsUsageCount(id: mdoc.id) }
				return mdoc
			}
			await MainActor.run { docModels = models }
		case .deferred:
			await MainActor.run { deferredDocuments = docs }
		case .pending:
			await MainActor.run { pendingDocuments = docs }
		}
	}

	private func refreshDocModel(_ doc: WalletStorage.Document, uiCulture: String?, docStatus: WalletStorage.DocumentStatus) async {
		if docStatus == .issued && docModels.first(where: { $0.id == doc.id}) == nil ||
			docStatus == .deferred && deferredDocuments.first(where: { $0.id == doc.id}) == nil ||
			docStatus == .pending && pendingDocuments.first(where: { $0.id == doc.id}) == nil {
			_ = await appendDocModel(doc, uiCulture: uiCulture)
		}
	}

	@discardableResult func appendDocModel(_ doc: WalletStorage.Document, uiCulture: String?) async -> DocClaimsModel? {
		switch doc.status {
		case .issued:
			let mdoc: DocClaimsModel? = Self.toClaimsModel(doc: doc, uiCulture: uiCulture, modelFactory: modelFactory)
			if let mdoc {
				mdoc.credentialsUsageCounts = try? await getCredentialsUsageCount(id: doc.id)
				await MainActor.run { docModels.append(mdoc) }
			} else { logger.error("Could not decode claims of \(doc.docType)") }
			return mdoc
		case .deferred:
			await MainActor.run { deferredDocuments.append(doc) }
			return nil
		case .pending:
			await MainActor.run { pendingDocuments.append(doc) }
			return nil
		}
	}

	func removePendingOrDeferredDoc(id: String) async throws {
		if let index = pendingDocuments.firstIndex(where: { $0.id == id }) {
			_ = await MainActor.run { pendingDocuments.remove(at: index) }
		}
		if deferredDocuments.firstIndex(where: { $0.id == id }) != nil {
			try await deleteDocument(id: id, status: .deferred)
		}
	}

	/// Set usage count for a document (for caching/logging purposes)
	/// - Parameters:
	///   - usageCount: The usage count information
	///   - id: The document identifier
	@MainActor
	public func setUsageCount(_ usageCount: CredentialsUsageCounts?, id: String) {
		let docModel = docModels.first(where: { $0.id == id })
		docModel?.credentialsUsageCounts = usageCount
	}

	/// Converts a `WalletStorage.Document` to an `DocClaimsModel` model using an optional `MdocModelFactory`.
	///
	/// - Parameters:
	///   - doc: The `WalletStorage.Document` to be converted.
	///   - modelFactory: An optional factory conforming to `MdocModelFactory` to create the model. Defaults to `nil`.
	///
	/// - Returns: An optional `DocClaimsModel` model created from the given document.
	public static func toClaimsModel(doc: WalletStorage.Document, uiCulture: String?, modelFactory: (any DocClaimsDecodableFactory)? = nil) -> DocClaimsModel? {
		switch doc.docDataFormat {
		case .cbor:	toCborMdocModel(doc: doc, uiCulture: uiCulture, modelFactory: modelFactory)
		case .sdjwt: toSdJwtDocModel(doc: doc, uiCulture: uiCulture, modelFactory: modelFactory)
		}
	}

	public static func toCborMdocModel(doc: WalletStorage.Document, uiCulture: String?, modelFactory: (any DocClaimsDecodableFactory)? = nil) -> DocClaimsModel? {
		guard let (d, _, _, _) = doc.getDataForTransfer() else { return nil }
		guard let iss = try? IssuerSigned(data: d.1.bytes) else { logger.error("Could not decode IssuerSigned"); return nil }
		let docMetadata = DocMetadata(from: doc.metadata)
		let docKeyInfo = DocKeyInfo(from: doc.docKeyInfo) ?? .default
		let md = docMetadata?.getMetadata(uiCulture: uiCulture)
		let cmd = md?.claimMetadata?.convertToCborClaimMetadata(uiCulture)
		let configuration = DocClaimsModelConfiguration(id: d.0, createdAt: doc.createdAt, docType: doc.docType, displayName: md?.displayName, display: md?.display, issuerDisplay: md?.issuerDisplay, credentialIssuerIdentifier: md?.credentialIssuerIdentifier, configurationIdentifier: md?.configurationIdentifier, validFrom: iss.validFrom, validUntil: iss.validUntil, statusIdentifier: iss.issuerAuth.statusIdentifier, credentialsUsageCounts: nil, credentialPolicy: docKeyInfo.credentialPolicy, secureAreaName: docKeyInfo.secureAreaName, modifiedAt: doc.modifiedAt, docClaims: [], docDataFormat: .cbor, hashingAlg: nil)
		var retModel: DocClaimsModel? = modelFactory?.makeClaimsDecodableFromCbor(configuration: configuration, issuerSigned: iss, displayNames: cmd?.displayNames, mandatory: cmd?.mandatory)
		if retModel == nil {
			let defModel: DocClaimsModel? = switch doc.docType {
			case EuPidModel.euPidDocType: EuPidModel(configuration: configuration, issuerSigned: iss, displayNames: cmd?.displayNames, mandatory: cmd?.mandatory)
			case IsoMdlModel.isoDocType: IsoMdlModel(configuration: configuration, issuerSigned: iss, displayNames: cmd?.displayNames, mandatory: cmd?.mandatory)
			default: nil
			}
			retModel = defModel ?? DocClaimsModel(configuration: configuration, issuerSigned: iss, displayNames: cmd?.displayNames, mandatory: cmd?.mandatory)
		}
		return retModel
	}

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
		let statusIdentifier: StatusIdentifier? = if let sd = recreatedClaims.json["status"].dictionary, let sld = sd["status_list"]?.dictionary, let uri = sld["uri"]?.string, let idx = sld["idx"]?.int32 { StatusIdentifier(idx: Int(idx), uriString: uri) } else { nil }
		let configuration = DocClaimsModelConfiguration(id: doc.id, createdAt: doc.createdAt, docType: doc.docType, displayName: docMetadata?.getDisplayName(uiCulture), display: docMetadata?.display, issuerDisplay: docMetadata?.issuerDisplay, credentialIssuerIdentifier: md?.credentialIssuerIdentifier, configurationIdentifier: md?.configurationIdentifier, validFrom: validFrom, validUntil: validUntil, statusIdentifier: statusIdentifier, credentialsUsageCounts: nil, credentialPolicy: docKeyInfo.credentialPolicy, secureAreaName: docKeyInfo.secureAreaName, modifiedAt: doc.modifiedAt, docClaims: docClaims, docDataFormat: .sdjwt, hashingAlg: recreatedClaims.hashingAlg)
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
			let resolved = json.arrayValue.map { element -> JSON in
				// Handle array elements with "..." (decoy digests)
				if element.type == .dictionary, let dots = element["..."].string {
					if let disclosure = hashToDisclosure[dots], disclosure.arrayValue.count >= 2 {
						return resolveNode(disclosure[1], hashToDisclosure: hashToDisclosure, hashingAlg: hashingAlg)
					}
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

	public func getDocIdsToPresentInfo(documents: [WalletStorage.Document]? = nil) async throws -> [String: DocPresentInfo] {
		let docs = if let documents { documents } else { try? await storageService.loadDocuments(status: .issued) }
		let dictValues = await docModels.asyncCompactMap { m -> (String, DocPresentInfo)? in
			guard let doc = docs?.first(where: { $0.id == m.id }), let dki = DocKeyInfo(from: doc.docKeyInfo) else { return nil }
			let bValid = (try? await hasAnyCredential(id: m.id)) ?? false
			guard bValid else { return nil }
			let docTypedData: DocTypedData? = switch m.docDataFormat {
				case .cbor: if let iss = try? IssuerSigned(data: doc.data.bytes) { .msoMdoc(iss) } else { nil }
				case .sdjwt: if let serString = String(data: doc.data, encoding: .utf8), let sd = try? CompactParser().getSignedSdJwt(serialisedString: serString) { .sdJwt(sd) } else { nil }
			}
			guard let docTypedData else { return nil }
			let presentInfo = DocPresentInfo(docType: m.docType, secureAreaName: dki.secureAreaName, docDataFormat: m.docDataFormat, displayName: m.displayName, docClaims: m.docClaims, typedData: docTypedData)
			return (m.id, presentInfo)
		}
		return Dictionary(uniqueKeysWithValues: dictValues)
	}

	public func hasAnyCredential(id: String) async throws -> Bool {
		let uc = try await getCredentialsUsageCount(id: id)
		return uc == nil || uc!.remaining > 0
	}

	public func getCredentialsUsageCount(id: String) async throws -> CredentialsUsageCounts? {
		let secureAreaName = getDocumentModel(id: id)?.secureAreaName
		return try await Self.getCredentialsUsageCount(id: id, secureAreaName: secureAreaName)
	}

	public static func getCredentialsUsageCount(id: String, secureAreaName: String?) async throws -> CredentialsUsageCounts? {
		let kbi = try await SecureAreaRegistry.shared.get(name: secureAreaName).getKeyBatchInfo(id: id)
		let remaining: Int? = if kbi.credentialPolicy == .rotateUse { nil } else { kbi.usedCounts.count { $0 == 0 } }
		return remaining.map { try! CredentialsUsageCounts(total: kbi.usedCounts.count, remaining: $0) }
	}

	/// Load documents from storage
	///
	/// Internally sets the ``docModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus, uiCulture: String?) async throws -> [WalletStorage.Document]?  {
		do {
			guard let docs = try await storageService.loadDocuments(status: status) else { return nil }
			let docs2 = docs.map { d in WalletStorage.Document(id: d.id, docType: d.docType, docDataFormat: d.docDataFormat, data: d.data, docKeyInfo: d.docKeyInfo, createdAt: d.createdAt, modifiedAt: d.modifiedAt, metadata: d.metadata, displayName: d.getDisplayName(uiCulture), status: d.status) }
			await refreshDocModels(docs2, uiCulture: uiCulture, docStatus: status)
			await refreshPublishedVars()
			return docs
		} catch {
			await setError(error)
			throw error
		}
	}

	/// Load a document from storage
	///
	/// - Returns: A ``WalletStorage.Document`` object
	/// - Parameter id: Identifier of document to load
	/// - Parameter status: Status of document to load
	@discardableResult public func loadDocument(id: String, uiCulture: String?, status: DocumentStatus) async throws -> WalletStorage.Document?  {
		do {
			guard let doc = try await storageService.loadDocument(id: id, status: status) else { return nil }
			await refreshDocModel(doc, uiCulture: uiCulture, docStatus: status)
			await refreshPublishedVars()
			return doc
		} catch {
			await setError(error)
			throw error
		}
	}

	func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: DocClaimsModel {
		docModels.first(where: { type(of: $0) == of}) as? T
	}

	func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: DocClaimsModel {
		docModels.filter({ type(of: $0) == of}).map { $0 as! T }
	}

	/// Get document model by index
	/// - Parameter index: Index in array of loaded models
	/// - Returns: The ``DocClaimsModel`` model
	func getDocumentModel(index: Int) -> DocClaimsModel? {
		guard index < docModels.count else { return nil }
		return docModels[index]
	}

	/// Get document model by id
	/// - Parameter id: The id of the document model to retrieve
	/// - Returns: The ``DocClaimsModel`` model
	public func getDocumentModel(id: String) ->  DocClaimsModel? {
		guard let i = docModels.map(\.id).firstIndex(of: id) else { return nil }
		return getDocumentModel(index: i)
	}

	/// Retrieves document models of a specified type.
	///
	/// - Parameter docType: A string representing the type of document to retrieve.
	/// - Returns: An array of objects conforming to the `DocClaimsModel` protocol.
	public func getDocumentModels(docType: String) -> [DocClaimsModel] {
		return (0..<docModels.count).compactMap { i in
			guard docModels[i].docType == docType else { return nil }
			return getDocumentModel(index: i)
		}
	}

	/// Delete document by id

	/// Deletes a document with the specified ID and status.
	/// - Parameters:
	///   - id: The unique identifier of the document to be deleted.
	///   - status: The current status of the document.
	///
	/// - Throws: An error if the document could not be deleted.
	public func deleteDocument(id: String, status: DocumentStatus) async throws {
		let index = switch status {
			case .issued: docModels.firstIndex(where: { $0.id == id});
			case .pending: pendingDocuments.firstIndex(where: { $0.id == id});
			default: deferredDocuments.firstIndex(where: { $0.id == id})
			}
		guard let index else { throw PresentationSession.makeError(str: "Document to delete \(id) not found") }
		do {
			try await storageService.deleteDocument(id: id, status: status)
			if status == .issued {
				_ = await MainActor.run { docModels.remove(at: index) }
				await refreshPublishedVars()
			}
			else if status == .pending { _ = await MainActor.run { pendingDocuments.remove(at: index) }}
			else if status == .deferred { _ = await MainActor.run { deferredDocuments.remove(at: index) }}
		} catch {
			await setError(error)
			throw error
		}
	}

	/// Delete documents
	/// - Parameter status: Status of documents to delete
	public func deleteDocuments(status: DocumentStatus) async throws {
		do {
			try await storageService.deleteDocuments(status: status)
			if status == .issued {
				await MainActor.run { docModels = [] }
				await refreshPublishedVars()
			} else if status == .pending {
				await MainActor.run { pendingDocuments.removeAll(keepingCapacity:false) }
			} else if status == .deferred {
				await MainActor.run { deferredDocuments.removeAll(keepingCapacity:false) }
			}
		} catch {
			await setError(error)
			throw error
		}
	}

	func setError(_ error: Error) async {
		await MainActor.run { uiError = WalletError(description: error.localizedDescription) }
	}

}
