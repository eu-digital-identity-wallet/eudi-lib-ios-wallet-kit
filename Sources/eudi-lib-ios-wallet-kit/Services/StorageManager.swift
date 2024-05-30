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
	/// Array of doc.types of documents loaded in the wallet
	public var docTypes: [String?] = []
	/// Array of document models loaded in the wallet
	@Published public var mdocModels: [MdocDecodable?] = []
	/// Array of document identifiers loaded in the wallet
	public var documentIds: [String?] = []
	var storageService: any DataStorageService
	/// Whether wallet currently has loaded data
	@Published public var hasData: Bool = false
	/// Whether wallet currently has loaded a document with doc.type included in the ``knownDocTypes`` array
	@Published public var hasWellKnownData: Bool = false
	/// Count of documents loaded in the wallet
	@Published public var docCount: Int = 0
	/// The driver license model loaded in the wallet
	@Published public var mdlModel: IsoMdlModel?
	/// The PID model loaded in the wallet
	@Published public var pidModel: EuPidModel?
	/// Other document models loaded in the wallet
	@Published public var otherModels: [GenericMdocModel] = []
	/// Error object with localized message
	@Published public var uiError: WalletError?
	let logger: Logger
	
	public init(storageService: any DataStorageService) {
		logger = Logger(label: "\(StorageManager.self)")
		self.storageService = storageService
	}
	
	@MainActor
	func refreshPublishedVars() {
		hasData = mdocModels.compactMap { $0 }.count > 0
		hasWellKnownData = hasData && !Set(docTypes.compactMap {$0}).isDisjoint(with: Self.knownDocTypes)
		docCount = mdocModels.compactMap { $0 }.count
		mdlModel = getTypedDoc()
		pidModel = getTypedDoc()
		otherModels = getTypedDocs()
	}
	
	@MainActor
	fileprivate func refreshDocModels(_ docs: [WalletStorage.Document]) {
		docTypes = docs.map(\.docType)
		mdocModels = docs.map { _ in nil }
		documentIds = docs.map(\.id)
		for (i, doc) in docs.enumerated() {
			mdocModels[i] = toModel(doc: doc)
		}
	}
	
	@MainActor
	@discardableResult func appendDocModel(_ doc: WalletStorage.Document) -> (any MdocDecodable)? {
		docTypes.append(doc.docType)
		documentIds.append(doc.id)
		let mdoc: (any MdocDecodable)? = toModel(doc: doc)
		mdocModels.append(mdoc)
		return mdoc
	}

	func toModel(doc: WalletStorage.Document) -> (any MdocDecodable)? {
		guard let (iss, dpk) = doc.getCborData() else { return nil }
		return switch doc.docType {
		case EuPidModel.euPidDocType: EuPidModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1)!
		case IsoMdlModel.isoDocType: IsoMdlModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1)!
		default: GenericMdocModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, title: doc.docType.translated())
		}
	}
	
	public func getDocIdsToTypes() -> [String: String] {
		Dictionary(uniqueKeysWithValues: documentIds.enumerated().compactMap { i, id in if let id, let dt = docTypes[i] { return (id, dt) } else { return nil} })
	}
	
	/// Load documents from storage
	///
	/// Internally sets the ``docTypes``, ``mdocModels``, ``documentIds``, ``mdocModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]?  {
		do {
			guard let docs = try storageService.loadDocuments() else { return nil }
			await refreshDocModels(docs)
			await refreshPublishedVars()
			return docs
		} catch {
			await setError(error)
			throw error
		}
	}
	
	func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: MdocDecodable {
		mdocModels.first(where: { $0 != nil && type(of: $0!) == of}) as? T
	}
	
	func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: MdocDecodable {
		mdocModels.filter({ $0 != nil && type(of: $0!) == of}).map { $0 as! T }
	}
	
	/// Get document model by index
	/// - Parameter index: Index in array of loaded models
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModel(index: Int) -> MdocDecodable? {
		guard index < mdocModels.count else { return nil }
		return mdocModels[index]
	}
	
	/// Get document model by id
	/// - Parameter id: The id of the document model to return
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModel(id: String) -> MdocDecodable? {
		guard let i = documentIds.firstIndex(of: id)  else { return nil }
		return getDocumentModel(index: i)
	}
	
	/// Get document model by docType
	/// - Parameter docType: The docType of the document model to return
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModels(docType: String) -> [MdocDecodable] {
		return (0..<docTypes.count).compactMap { i in
			guard let dt = docTypes[i], dt == docType else { return nil }
			return getDocumentModel(index: i)
		}
	}
	/// Delete documents by docType
	/// - Parameter docType: Document type
	public func deleteDocuments(docType: String) async throws {
		for i in (0..<docTypes.count) {
			guard let dt = docTypes[i], dt == docType else { continue }
			do {
				try await deleteDocument(index: i)
			} catch {
				await setError(error)
				throw error
			}
		}
	}
	/// Delete document by id
	/// - Parameter id: Document id
	public func deleteDocument(id: String) async throws {
		guard let i: Array<String?>.Index = documentIds.firstIndex(of: id)  else { return }
		do {
			try await deleteDocument(index: i)
		} catch {
			await setError(error)
			throw error
		}
	}
	/// Delete document by Index
	/// - Parameter index: Index in array of loaded models
	public func deleteDocument(index: Int) async throws {
		guard index < documentIds.count, let id = documentIds[index] else { return }
		do {
			try storageService.deleteDocument(id: id)
			await MainActor.run {
				if docTypes[index] == IsoMdlModel.isoDocType { mdlModel = nil }
				if docTypes[index] == EuPidModel.euPidDocType { pidModel = nil }
				documentIds[index] = nil; mdocModels[index] = nil; docTypes[index] = nil
			}
			await refreshPublishedVars()
		} catch {
			await setError(error)
			throw error
		}
	}
	
	/// Delete documenmts
	public func deleteDocuments() async throws {
		do {
			try storageService.deleteDocuments()
			await MainActor.run { documentIds = []; mdocModels = []; docTypes = []; mdlModel = nil; pidModel = nil }
			await refreshPublishedVars()
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



