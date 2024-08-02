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
public class StorageManager: ObservableObject {
	public static let knownDocTypes = [EuPidModel.euPidDocType, IsoMdlModel.isoDocType]
	/// Array of document models loaded in the wallet
	@Published public private(set) var mdocModels: [any MdocDecodable] = []
	@Published public private(set) var deferredDocuments: [WalletStorage.Document] = []
	var storageService: any DataStorageService
	/// Whether wallet currently has loaded data
	@Published public private(set) var hasData: Bool = false
	/// Whether wallet currently has loaded a document with doc.type included in the ``knownDocTypes`` array
	@Published public private(set) var hasWellKnownData: Bool = false
	/// Count of documents loaded in the wallet
	@Published public private(set) var docCount: Int = 0
	/// The first driver license model loaded in the wallet (deprecated)
	@Published public private(set) var mdlModel: IsoMdlModel?
	/// The first PID model loaded in the wallet (deprecated)
	@Published public private(set) var pidModel: EuPidModel?
	/// Error object with localized message
	@Published public var uiError: WalletError?
	var modelFactory: (any MdocModelFactory.Type)?
	
	public init(storageService: any DataStorageService, modelFactory: (any MdocModelFactory.Type)? = nil) {
		self.storageService = storageService
		self.modelFactory = modelFactory
	}
	
	@MainActor
	func refreshPublishedVars() {
		hasData = mdocModels.count > 0
		hasWellKnownData = hasData && !Set(mdocModels.map(\.docType)).isDisjoint(with: Self.knownDocTypes)
		docCount = mdocModels.count
		mdlModel = getTypedDoc()
		pidModel = getTypedDoc()
	}
	
	@MainActor
	fileprivate func refreshDocModels(_ docs: [WalletStorage.Document], docStatus: WalletStorage.DocumentStatus) {
		switch docStatus {
		case .issued:
			mdocModels = docs.compactMap(toModel(doc:))
		case .deferred:
			deferredDocuments = docs
		}
	}
	
	@MainActor
	@discardableResult func appendDocModel(_ doc: WalletStorage.Document) -> (any MdocDecodable)? {
		switch doc.status {
		case .issued:
			let mdoc: (any MdocDecodable)? = toModel(doc: doc)
			if let mdoc { mdocModels.append(mdoc) }
			return mdoc
		case .deferred:
			deferredDocuments.append(doc)
			return nil
		}
	}

	func toModel(doc: WalletStorage.Document) -> (any MdocDecodable)? {
		guard let (iss, dpk) = doc.getCborData() else { return nil }
		var retModel: (any MdocDecodable)? = self.modelFactory?.makeMdocDecodable(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, displayName: doc.displayName)
		if retModel == nil {
			let defModel: (any MdocDecodable)? = switch doc.docType {
			case EuPidModel.euPidDocType: EuPidModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, displayName: doc.displayName)
			case IsoMdlModel.isoDocType: IsoMdlModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, displayName: doc.displayName)
			default: nil
			}
			retModel = defModel ?? GenericMdocModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, displayName: doc.displayName)
		}
		return retModel
	}
	
	public func getDocIdsToTypes() -> [String: String] {
		Dictionary(uniqueKeysWithValues: mdocModels.map { m in (m.id, m.docType) })
	}
	
	/// Load documents from storage
	///
	/// Internally sets the ``mdocModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus) async throws -> [WalletStorage.Document]?  {
		do {
			guard let docs = try storageService.loadDocuments(status: status) else { return nil }
			await refreshDocModels(docs, docStatus: status)
			await refreshPublishedVars()
			return docs
		} catch {
			await setError(error)
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
	/// - Parameter id: The id of the document model to return
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModel(id: String) ->  (any MdocDecodable)? {
		guard let i = mdocModels.map(\.id).firstIndex(of: id)  else { return nil }
		return getDocumentModel(index: i)
	}
	
	/// Get document model by docType
	/// - Parameter docType: The docType of the document model to return
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModels(docType: String) -> [any MdocDecodable] {
		return (0..<mdocModels.count).compactMap { i in
			guard mdocModels[i].docType == docType else { return nil }
			return getDocumentModel(index: i)
		}
	}

	/// Delete document by id
	/// - Parameter id: Document id
	public func deleteDocument(id: String, status: DocumentStatus) async throws {
		let index = switch status { case .issued: mdocModels.firstIndex(where: { $0.id == id}); default: deferredDocuments.firstIndex(where: { $0.id == id})  }
		guard let index else { throw WalletError(description: "Document not found") }
		do {
			try storageService.deleteDocument(id: id, status: status)
			if status == .issued {
				await MainActor.run {
					if mdocModels[index].docType == IsoMdlModel.isoDocType { mdlModel = nil }
					if mdocModels[index].docType == EuPidModel.euPidDocType { pidModel = nil }
					mdocModels.remove(at: index)
				}
				await refreshPublishedVars()
			} else if status == .deferred {
				await MainActor.run { _ = deferredDocuments.remove(at: index) }
			}
		} catch {
			await setError(error)
			throw error
		}
	}
	
	/// Delete documenmts
	public func deleteDocuments(status: DocumentStatus) async throws {
		do {
			try storageService.deleteDocuments(status: status)
			if status == .issued {
				await MainActor.run { mdocModels = []; mdlModel = nil; pidModel = nil }
				await refreshPublishedVars()
			} else if status == .deferred {
				await MainActor.run { deferredDocuments.removeAll(keepingCapacity:false) }
			}
		} catch {
			await setError(error)
			throw error
		}
	}
	
	@MainActor
	func setError(_ error: Error) {
		uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code, userInfo: (error as NSError).userInfo)
	}
	
}




