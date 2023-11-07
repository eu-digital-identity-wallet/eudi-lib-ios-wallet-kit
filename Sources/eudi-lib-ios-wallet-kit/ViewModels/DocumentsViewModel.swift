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
import SwiftUI
import Logging

/// Sample data storage service
public class DocumentsViewModel: ObservableObject {
	public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
	public var mdocModels: [MdocDecodable?]
	@Published public var hasModels: [Bool?]
	var storageService: any DataStorageService
	@AppStorage("DebugDisplay") var debugDisplay: Bool = false
	@Published public var hasData: Bool = false
	@Published public var docCount: Int = 0
	let logger: Logger

	public init(storageService: any DataStorageService) {
		logger = Logger(label: "logger")
		self.storageService = storageService
		mdocModels = Self.knownDocTypes.map { _ in nil }
		hasModels = Self.knownDocTypes.map { _ in nil }
	}

	fileprivate func refreshStatistics() {
		hasData = !hasModels.compactMap { $0 }.allSatisfy { $0 == false}
		docCount = hasModels.filter { $0 == true }.count
	}
	
	public func getDoc(i: Int) -> MdocDecodable? {
		guard i < Self.knownDocTypes.count else { return nil }
		if hasModels[i] == false { return nil }
		if let model = mdocModels[i] { if hasModels[i] == nil { hasModels[i] = true; refreshStatistics() }; return model }
		var model: MdocDecodable?
		guard let doc = try? storageService.loadDocument(docType: Self.knownDocTypes[i]) else { hasModels[i] = false; return nil }
		guard let sr = doc.data.decodeJSON(type: SignUpResponse.self) else { hasModels[i] = false; return nil }
		guard let dr = sr.deviceResponse, let dpk = sr.devicePrivateKey else { hasModels[i] = false; return nil }
		model = switch i {
		case 0: EuPidModel(response: dr, devicePrivateKey: dpk)
		case 1: IsoMdlModel(response: dr, devicePrivateKey: dpk)
		default: nil
		}
		hasModels[i] = model != nil; mdocModels[i] = model
		refreshStatistics()
		return model
	}
	
	public func removeDoc(i: Int) {
		guard i < Self.knownDocTypes.count else { return }
		try? storageService.deleteDocument(docType: Self.knownDocTypes[i])
		hasModels[i] = false; mdocModels[i] = nil
		refreshStatistics()
	}


}
