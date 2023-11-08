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
import MdocDataModel18013
import WalletStorage
import Logging

/// Sample data storage service
public class DocumentsViewModel: ObservableObject {
	public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
	@Published  public var mdocModels: [MdocDecodable?] = []
	public var modelIds: [String?] = []
	var storageService: any DataStorageService
	@Published public var hasData: Bool = false
	@Published public var docCount: Int = 0
	let logger: Logger

	public init(storageService: any DataStorageService) {
		logger = Logger(label: "logger")
		self.storageService = storageService
	}

	fileprivate func refreshStatistics() {
		hasData = modelIds.compactMap { $0 }.count > 0
		docCount = modelIds.compactMap { $0 }.count
	}
	
	func loadDocuments() {
		guard let docs = try? storageService.loadDocuments() else { return }
		mdocModels = Self.knownDocTypes.map { _ in nil }
		modelIds = Self.knownDocTypes.map { _ in nil }
		for (i, docType) in DocumentsViewModel.knownDocTypes.enumerated() {
			guard let doc = docs.first(where: { $0.docType == docType}) else { continue }
			guard let sr = doc.data.decodeJSON(type: SignUpResponse.self), let dr = sr.deviceResponse, let dpk = sr.devicePrivateKey else { continue
			}
			modelIds[i] = doc.id
			mdocModels[i] = switch i {
			case 0: EuPidModel(response: dr, devicePrivateKey: dpk)
			case 1: IsoMdlModel(response: dr, devicePrivateKey: dpk)
			default: nil
			}
		}
		refreshStatistics()
	}
	
	public func getDoc(i: Int) -> MdocDecodable? {
		guard i < Self.knownDocTypes.count, i < mdocModels.count else { return nil }
		return mdocModels[i]
	}
	
	public func removeDoc(i: Int) {
		guard i < Self.knownDocTypes.count, let id = modelIds[i] else { return }
		try? storageService.deleteDocument(id: id)
		modelIds[i] = nil; mdocModels[i] = nil
		refreshStatistics()
	}


}
