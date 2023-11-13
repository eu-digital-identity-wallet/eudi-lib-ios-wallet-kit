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

/// Sample data storage service
public class StorageModel: ObservableObject {
	public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
	public var docTypes: [String?] = []
	@Published public var mdocModels: [MdocDecodable?] = []
	public var modelIds: [String?] = []
	var storageService: any DataStorageService
	@Published public var hasData: Bool = false
	@Published public var hasWellKnownData: Bool = false
	@Published public var docCount: Int = 0
	@Published public var mdlModel: IsoMdlModel?
	@Published public var pidModel: EuPidModel?
	@Published public var otherModels: [GenericMdocModel] = []
	let logger: Logger

	public init(storageService: any DataStorageService) {
		logger = Logger(label: "logger")
		self.storageService = storageService
		loadDocuments()
	}

	fileprivate func refreshPublishedVars() {
		hasWellKnownData = !Set(docTypes.compactMap {$0}).isDisjoint(with: Self.knownDocTypes)
		hasData = modelIds.compactMap { $0 }.count > 0
		docCount = modelIds.compactMap { $0 }.count
		mdlModel = getTypedDoc()
		pidModel = getTypedDoc()
		otherModels = getTypedDocs()
	}
	
	@discardableResult func loadDocuments() -> [WalletStorage.Document]? {
		guard let docs = try? storageService.loadDocuments() else { return nil }
		docTypes = docs.map(\.docType)
		mdocModels = docs.map { _ in nil }
		modelIds = docs.map(\.id)
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
	
	public func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: MdocDecodable {
		mdocModels.first(where: { $0 != nil && type(of: $0!) == of}) as? T
	}
	
	public func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: MdocDecodable {
		mdocModels.filter({ $0 != nil && type(of: $0!) == of}).map { $0 as! T }
	}
	
	public func getDoc(index: Int) -> MdocDecodable? {
		guard index < mdocModels.count else { return nil }
		return mdocModels[index]
	}
	
	public func getDoc(docType: String) -> MdocDecodable? {
		guard let i = docTypes.firstIndex(of: docType)  else { return nil }
		return getDoc(index: i)
	}
	
	public func removeDoc(docType: String) {
		guard let i = docTypes.firstIndex(of: docType)  else { return }
		removeDoc(index: i)
	}
	
	public func removeDoc(index: Int) {
		guard index < modelIds.count, let id = modelIds[index] else { return }
		try? storageService.deleteDocument(id: id)
		modelIds[index] = nil; mdocModels[index] = nil; docTypes[index] = nil
		refreshPublishedVars()
	}


}
