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

/// Storage manager. Provides services and view models
public class StorageManager: ObservableObject, @unchecked Sendable {
	/// A static constant array containing known document types.
	/// This array includes document types from `EuPidModel` and `IsoMdlModel`.
	/// - Note: The document types included are `euPidDocType` and `isoDocType`.
	public static let knownDocTypes = [EuPidModel.euPidDocType, IsoMdlModel.isoDocType]
	/// A published property that holds an array of CBOR decoded models conforming to the `DocClaimsDecodable` protocol.
	/// - Note: The `@Published` property wrapper is used to allow SwiftUI views to automatically update when the value changes.
	@Published public private(set) var docModels: [any DocClaimsDecodable] = []
	/// A published property that holds an array of deferred documents.
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
			let models = docs.compactMap { Self.toClaimsModel(doc:$0, uiCulture: uiCulture, modelFactory: modelFactory) }
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
	
	@discardableResult func appendDocModel(_ doc: WalletStorage.Document, uiCulture: String?) async -> (any DocClaimsDecodable)? {
		switch doc.status {
		case .issued:
			let mdoc: (any DocClaimsDecodable)? = Self.toClaimsModel(doc: doc, uiCulture: uiCulture, modelFactory: modelFactory)
			if let mdoc { await MainActor.run { docModels.append(mdoc) } }
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

	/// Converts a `WalletStorage.Document` to an `DocClaimsDecodable` model using an optional `MdocModelFactory`.
	///
	/// - Parameters:
	///   - doc: The `WalletStorage.Document` to be converted.
	///   - modelFactory: An optional factory conforming to `MdocModelFactory` to create the model. Defaults to `nil`.
	///
	/// - Returns: An optional `DocClaimsDecodable` model created from the given document.
	public static func toClaimsModel(doc: WalletStorage.Document, uiCulture: String?, modelFactory: (any DocClaimsDecodableFactory)? = nil) -> (any DocClaimsDecodable)? {
		switch doc.docDataFormat {
		case .cbor:	toCborMdocModel(doc: doc, uiCulture: uiCulture, modelFactory: modelFactory)
		case .sdjwt: toSdJwtDocModel(doc: doc, uiCulture: uiCulture)
		}
	}

	public static func toCborMdocModel(doc: WalletStorage.Document, uiCulture: String?, modelFactory: (any DocClaimsDecodableFactory)? = nil) -> (any DocClaimsDecodable)? {
		guard let (d, _, _) = doc.getDataForTransfer(), let iss = IssuerSigned(data: d.1.bytes) else { return nil }
		let docMetadata: DocMetadata? = DocMetadata(from: doc.metadata)
		let md = docMetadata?.getCborClaimMetadata(uiCulture: uiCulture)
		var retModel: (any DocClaimsDecodable)? = modelFactory?.makeClaimsDecodableFromCbor(id: d.0, createdAt: doc.createdAt, issuerSigned: iss, displayName: md?.0, claimDisplayNames: md?.1, mandatoryClaims: md?.2, claimValueTypes: md?.3)
		if retModel == nil {
			let defModel: (any DocClaimsDecodable)? = switch doc.docType {
			case EuPidModel.euPidDocType: EuPidModel(id: d.0, createdAt: doc.createdAt, issuerSigned: iss, displayName: md?.0, claimDisplayNames: md?.1, mandatoryClaims: md?.2, claimValueTypes: md?.3)
			case IsoMdlModel.isoDocType: IsoMdlModel(id: d.0, createdAt: doc.createdAt, issuerSigned: iss, displayName: md?.0, claimDisplayNames: md?.1, mandatoryClaims: md?.2, claimValueTypes: md?.3)
			default: nil
			}
			retModel = defModel ?? GenericMdocModel(id: d.0, createdAt: doc.createdAt, issuerSigned: iss, docType: doc.docType ?? docMetadata?.docType ?? d.0, displayName: md?.0, claimDisplayNames: md?.1, mandatoryClaims: md?.2, claimValueTypes: md?.3)
		}
		return retModel
	}

	public static func toSdJwtDocModel(doc: WalletStorage.Document, uiCulture: String?, modelFactory: (any DocClaimsDecodableFactory)? = nil) -> (any DocClaimsDecodable)? {
		var docClaims = [DocClaim]()
		let docMetadata: DocMetadata? = DocMetadata(from: doc.metadata)
		let md = docMetadata?.getFlatClaimMetadata(uiCulture: uiCulture)
		let parser = CompactParser()
		guard let serString = String(data: doc.data, encoding: .utf8), let sdJwt = try? parser.getSignedSdJwt(serialisedString: serString), let result = try? sdJwt.recreateClaims() else { return nil }
		if let cs = result.recreatedClaims.toClaimsArray(md?.1, md?.2, md?.3)?.0 { docClaims.append(contentsOf: cs) }
		var type = docClaims.first(where: { $0.name == "vct"})?.stringValue
		if type == nil || type!.isEmpty { type = docClaims.first(where: { $0.name == "evidence"})?.children?.first(where: { $0.name == "type"})?.stringValue }
		return GenericMdocModel(id: doc.id, createdAt: doc.createdAt, docType: doc.docType ?? type, displayName: docMetadata?.getDisplayName(uiCulture), docClaims: docClaims, docDataFormat: .sdjwt)
	}

	public func getDocIdsToTypes() -> [String: (String, DocDataFormat, String?)] {
		Dictionary(uniqueKeysWithValues: docModels.filter { $0.docType != nil}.map { m in (m.id, (m.docType!, m.docDataFormat, m.displayName) ) })
	}
	
	/// Load documents from storage
	///
	/// Internally sets the ``docModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus, uiCulture: String?) async throws -> [WalletStorage.Document]?  {
		do {
			guard let docs = try await storageService.loadDocuments(status: status) else { return nil }
			let docs2 = docs.map { d in WalletStorage.Document(id: d.id, docType: d.docType, docDataFormat: d.docDataFormat, data: d.data, secureAreaName: d.secureAreaName,
			 createdAt: d.createdAt, modifiedAt: d.modifiedAt, metadata: d.metadata, displayName: d.getDisplayName(uiCulture), status: d.status)   }
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
	
	func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: DocClaimsDecodable {
		docModels.first(where: { type(of: $0) == of}) as? T
	}
	
	func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: DocClaimsDecodable {
		docModels.filter({ type(of: $0) == of}).map { $0 as! T }
	}
	
	/// Get document model by index
	/// - Parameter index: Index in array of loaded models
	/// - Returns: The ``DocClaimsDecodable`` model
	func getDocumentModel(index: Int) -> (any DocClaimsDecodable)? {
		guard index < docModels.count else { return nil }
		return docModels[index]
	}
	
	/// Get document model by id
	/// - Parameter id: The id of the document model to retrieve
	/// - Returns: The ``DocClaimsDecodable`` model
	public func getDocumentModel(id: String) ->  (any DocClaimsDecodable)? {
		guard let i = docModels.map(\.id).firstIndex(of: id)  else { return nil }
		return getDocumentModel(index: i)
	}
	
	/// Retrieves document models of a specified type.
	///
	/// - Parameter docType: A string representing the type of document to retrieve.
	/// - Returns: An array of objects conforming to the `DocClaimsDecodable` protocol.
	public func getDocumentModels(docType: String) -> [any DocClaimsDecodable] {
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
		let index = switch status { case .issued: docModels.firstIndex(where: { $0.id == id}); default: deferredDocuments.firstIndex(where: { $0.id == id})  }
		guard let index else { throw WalletError(description: "Document not found") }
		do {
			try await storageService.deleteDocument(id: id, status: status)
			if status == .issued {
				_ = await MainActor.run { docModels.remove(at: index) }
				await refreshPublishedVars()
			} else if status == .deferred {
				_ = await MainActor.run { deferredDocuments.remove(at: index) }
			}
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
			} else if status == .deferred {
				await MainActor.run { deferredDocuments.removeAll(keepingCapacity:false) }
			}
		} catch {
			await setError(error)
			throw error
		}
	}
	
	func setError(_ error: Error) async {
		await MainActor.run { uiError = WalletError(description: error.localizedDescription, userInfo: (error as NSError).userInfo) }
	}
	
}




