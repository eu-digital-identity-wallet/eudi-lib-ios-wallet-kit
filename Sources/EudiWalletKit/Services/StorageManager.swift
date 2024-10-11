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

/// Storage manager. Provides services and view models
public class StorageManager: ObservableObject, @unchecked Sendable {
	/// A static constant array containing known document types.
	/// This array includes document types from `EuPidModel` and `IsoMdlModel`.
	/// - Note: The document types included are `euPidDocType` and `isoDocType`.
	public static let knownDocTypes = [EuPidModel.euPidDocType, IsoMdlModel.isoDocType]
	/// A published property that holds an array of CBOR decoded models conforming to the `MdocDecodable` protocol.
	/// - Note: The `@Published` property wrapper is used to allow SwiftUI views to automatically update when the value changes.
	@Published public private(set) var mdocModels: [any MdocDecodable] = []
	/// A published property that holds an array of deferred documents.
	/// - Note: This property is used to store documents that are deferred for later processing.
	@Published public private(set) var deferredDocuments: [WalletStorage.Document] = []
	/// A published property that holds an array of pending documents.
	@Published public private(set) var pendingDocuments: [WalletStorage.Document] = []
	var storageService: any DataStorageService
	/// Whether wallet currently has loaded data
	@Published public private(set) var hasData: Bool = false
	/// Whether wallet currently has loaded a document with doc.type included in the ``knownDocTypes`` array
	@Published public private(set) var hasWellKnownData: Bool = false
	/// Count of documents loaded in the wallet
	@Published public private(set) var docCount: Int = 0
	/// Error object with localized message
	@Published public var uiError: WalletError?
	var modelFactory: (any MdocModelFactory)?
	
	public init(storageService: any DataStorageService, modelFactory: (any MdocModelFactory)? = nil) {
		self.storageService = storageService
		self.modelFactory = modelFactory
	}
	
	func refreshPublishedVars() async {
		await MainActor.run {
			hasData = !mdocModels.isEmpty || !deferredDocuments.isEmpty
			hasWellKnownData = hasData && !Set(mdocModels.map(\.docType)).isDisjoint(with: Self.knownDocTypes)
			docCount = mdocModels.count
		}
	}
	
	/// Refreshes the document models with the specified status.
	/// 
	/// - Parameters:
	///   - docs: An array of `WalletStorage.Document` objects to be refreshed.
	///   - docStatus: The status of the documents.
	private func refreshDocModels(_ docs: [WalletStorage.Document], docStatus: WalletStorage.DocumentStatus) async {
		switch docStatus {
		case .issued:
			let models = docs.compactMap { Self.toMdocModel(doc:$0, modelFactory: modelFactory) }
			await MainActor.run { mdocModels = models }
		case .deferred:
			await MainActor.run { deferredDocuments = docs }
		case .pending:
			await MainActor.run { pendingDocuments = docs }
		}
	}

	@MainActor
	private func refreshDocModel(_ doc: WalletStorage.Document, docStatus: WalletStorage.DocumentStatus) async {
		if docStatus == .issued && mdocModels.first(where: { $0.id == doc.id}) == nil ||
			docStatus == .deferred && deferredDocuments.first(where: { $0.id == doc.id}) == nil ||
			docStatus == .pending && pendingDocuments.first(where: { $0.id == doc.id}) == nil {
			_ = await appendDocModel(doc)
		}
	}
	
	@discardableResult func appendDocModel(_ doc: WalletStorage.Document) async -> (any MdocDecodable)? {
		switch doc.status {
		case .issued:
			let mdoc: (any MdocDecodable)? = Self.toMdocModel(doc: doc, modelFactory: modelFactory)
			if let mdoc { await MainActor.run { mdocModels.append(mdoc) } }
			return mdoc
		case .deferred:
			await MainActor.run { deferredDocuments.append(doc) }
			return nil
		case .pending:
			await MainActor.run { pendingDocuments.append(doc) }
			return nil
		}
	}
	
	@MainActor
	func removePendingOrDeferredDoc(id: String) async throws {
		if let index = pendingDocuments.firstIndex(where: { $0.id == id }) {
			pendingDocuments.remove(at: index)
		}
		if deferredDocuments.firstIndex(where: { $0.id == id }) != nil {
			try await deleteDocument(id: id, status: .deferred)
		}
	}

	/// Converts a `WalletStorage.Document` to an `MdocDecodable` model using an optional `MdocModelFactory`.
	///
	/// - Parameters:
	///   - doc: The `WalletStorage.Document` to be converted.
	///   - modelFactory: An optional factory conforming to `MdocModelFactory` to create the model. Defaults to `nil`.
	///
	/// - Returns: An optional `MdocDecodable` model created from the given document.
	public static func toMdocModel(doc: WalletStorage.Document, modelFactory: (any MdocModelFactory)? = nil) -> (any MdocDecodable)? {
		guard let (iss, dpk) = doc.getCborData() else { return nil }
		var retModel: (any MdocDecodable)? = modelFactory?.makeMdocDecodable(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, displayName: doc.displayName, statusDescription: doc.statusDescription)
		if retModel == nil {
			let defModel: (any MdocDecodable)? = switch doc.docType {
			case EuPidModel.euPidDocType: EuPidModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, displayName: doc.displayName, statusDescription: doc.statusDescription)
			case IsoMdlModel.isoDocType: IsoMdlModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, displayName: doc.displayName, statusDescription: doc.statusDescription)
			default: nil
			}
			retModel = defModel ?? GenericMdocModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, displayName: doc.displayName, statusDescription: doc.statusDescription)
		}
		return retModel
	}
	
	public func getDocIdsToTypes() -> [String: (String, String?)] {
		Dictionary(uniqueKeysWithValues: mdocModels.map { m in (m.id, (m.docType, m.displayName) ) })
	}
	
	/// Load documents from storage
	///
	/// Internally sets the ``mdocModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus) async throws -> [WalletStorage.Document]?  {
		do {
			guard let docs = try await storageService.loadDocuments(status: status) else { return nil }
			await refreshDocModels(docs, docStatus: status)
			await refreshPublishedVars()
			return docs
		} catch {
			setError(error)
			throw error
		}
	}

	/// Load a document from storage
	///
	/// - Returns: A ``WalletStorage.Document`` object
	/// - Parameter id: Identifier of document to load
	/// - Parameter status: Status of document to load
	@discardableResult public func loadDocument(id: String, status: DocumentStatus) async throws -> WalletStorage.Document?  {
		do {
			guard let doc = try await storageService.loadDocument(id: id, status: status) else { return nil }
			await refreshDocModel(doc, docStatus: status)
			await refreshPublishedVars()
			return doc
		} catch {
			setError(error)
			throw error
		}
	}
	
	func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: MdocDecodable {
		mdocModels.first(where: { type(of: $0) == of}) as? T
	}
	
	func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: MdocDecodable {
		mdocModels.filter({ type(of: $0) == of}).map { $0 as! T }
	}
	
	/// Get document model by index
	/// - Parameter index: Index in array of loaded models
	/// - Returns: The ``MdocDecodable`` model
	func getDocumentModel(index: Int) -> (any MdocDecodable)? {
		guard index < mdocModels.count else { return nil }
		return mdocModels[index]
	}
	
	/// Get document model by id
	/// - Parameter id: The id of the document model to retrieve
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModel(id: String) ->  (any MdocDecodable)? {
		guard let i = mdocModels.map(\.id).firstIndex(of: id)  else { return nil }
		return getDocumentModel(index: i)
	}
	
	/// Retrieves document models of a specified type.
	///
	/// - Parameter docType: A string representing the type of document to retrieve.
	/// - Returns: An array of objects conforming to the `MdocDecodable` protocol.
	public func getDocumentModels(docType: String) -> [any MdocDecodable] {
		return (0..<mdocModels.count).compactMap { i in
			guard mdocModels[i].docType == docType else { return nil }
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
		let index = switch status { case .issued: mdocModels.firstIndex(where: { $0.id == id}); default: deferredDocuments.firstIndex(where: { $0.id == id})  }
		guard let index else { throw WalletError(description: "Document not found") }
		do {
			try await storageService.deleteDocument(id: id, status: status)
			if status == .issued {
				_ = mdocModels.remove(at: index)
				await refreshPublishedVars()
			} else if status == .deferred {
				_ = deferredDocuments.remove(at: index)
			}
		} catch {
			setError(error)
			throw error
		}
	}
	
	/// Delete documents
	/// - Parameter status: Status of documents to delete
	public func deleteDocuments(status: DocumentStatus) async throws {
		do {
			try await storageService.deleteDocuments(status: status)
			if status == .issued {
				mdocModels = [];
				await refreshPublishedVars()
			} else if status == .deferred {
				deferredDocuments.removeAll(keepingCapacity:false) 
			}
		} catch {
			setError(error)
			throw error
		}
	}
	
	func setError(_ error: Error) {
		uiError = WalletError(description: error.localizedDescription, userInfo: (error as NSError).userInfo)
	}
	
}




