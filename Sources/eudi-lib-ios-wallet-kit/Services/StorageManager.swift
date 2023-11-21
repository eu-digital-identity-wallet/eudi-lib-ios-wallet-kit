 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */
 

import Foundation
import SwiftCBOR
import MdocDataModel18013
import WalletStorage
import Logging

/// Storage manager. Provides services and view models
public class StorageManager: ObservableObject {
	public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
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
	let logger: Logger

	public init(storageService: any DataStorageService) {
		logger = Logger(label: "\(StorageManager.self)")
		self.storageService = storageService
	}

	fileprivate func refreshPublishedVars() {
		hasWellKnownData = !Set(docTypes.compactMap {$0}).isDisjoint(with: Self.knownDocTypes)
		hasData = documentIds.compactMap { $0 }.count > 0
		docCount = documentIds.compactMap { $0 }.count
		mdlModel = getTypedDoc()
		pidModel = getTypedDoc()
		otherModels = getTypedDocs()
	}
	
	/// Load documents from storage
	///
	/// Internally sets the ``docTypes``, ``mdocModels``, ``documentIds``, ``mdocModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments() -> [WalletStorage.Document]? {
		guard let docs = try? storageService.loadDocuments() else { return nil }
		docTypes = docs.map(\.docType)
		mdocModels = docs.map { _ in nil }
		documentIds = docs.map(\.id)
		for (i, doc) in docs.enumerated() {
			guard let sr = doc.data.decodeJSON(type: SignUpResponse.self), let dr = sr.deviceResponse, let dpk = sr.devicePrivateKey else { continue }
			mdocModels[i] = switch doc.docType {
			case EuPidModel.EuPidDocType: EuPidModel(response: dr, devicePrivateKey: dpk)
			case IsoMdlModel.isoDocType: IsoMdlModel(response: dr, devicePrivateKey: dpk)
			default: GenericMdocModel(response: dr, devicePrivateKey: dpk, docType: doc.docType, title: doc.docType.translated())
			}
		}
		refreshPublishedVars()
		return docs
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
	
	/// Get document model by docType
	/// - Parameter docType: The docType of the document model to return
	/// - Returns: The ``MdocDecodable`` model
	public func getDocumentModel(docType: String) -> MdocDecodable? {
		guard let i = docTypes.firstIndex(of: docType)  else { return nil }
		return getDocumentModel(index: i)
	}
	
	/// Delete document by docType
	/// - Parameter docType: Document type
	public func deleteDocument(docType: String) {
		guard let i = docTypes.firstIndex(of: docType)  else { return }
		deleteDocument(index: i)
	}
	
	/// Delete document by Index
	/// - Parameter index: Index in array of loaded models
	public func deleteDocument(index: Int) {
		guard index < documentIds.count, let id = documentIds[index] else { return }
		try? storageService.deleteDocument(id: id)
		documentIds[index] = nil; mdocModels[index] = nil; docTypes[index] = nil
		refreshPublishedVars()
	}


}
