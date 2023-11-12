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
public class DocumentsViewModel: ObservableObject {
	public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
	public var docTypes: [String?] = []
	@Published public var mdocModels: [MdocDecodable?] = []
	public var modelIds: [String?] = []
	var storageService: any DataStorageService
	@Published public var hasData: Bool = false
	@Published public var hasWellKnownData: Bool = false
	@Published public var docCount: Int = 0
	let logger: Logger

	public init(storageService: any DataStorageService) {
		logger = Logger(label: "logger")
		self.storageService = storageService
		loadDocuments()
	}

	fileprivate func refreshStatistics() {
		hasWellKnownData = !Set(docTypes.compactMap {$0}).isDisjoint(with: Self.knownDocTypes)
		hasData = modelIds.compactMap { $0 }.count > 0
		docCount = modelIds.compactMap { $0 }.count
	}
	
	/// Decompose CBOR device responses from data
	/// 
	/// A data file may contain signup responses with many documents (doc.types).
	/// - Parameter data: Data from file or memory
	/// - Returns:  separate ``MdocDataModel18013.DeviceResponse`` objects for each doc.type
	public static func decomposeCBORDeviceResponse(data: Data) -> [(docType: String, dr: MdocDataModel18013.DeviceResponse)]? {
		guard let sr = data.decodeJSON(type: SignUpResponse.self), let dr = sr.deviceResponse, let docs = dr.documents else { return nil }
		return docs.map { (docType: $0.docType, dr: DeviceResponse(version: dr.version, documents: [$0], status: dr.status)) }
	}
	
	/// Decompose CBOR signup responses from data
	///
	/// A data file may contain signup responses with many documents (doc.types).
	/// - Parameter data: Data from file or memory
	/// - Returns:  separate json serialized signup response objects for each doc.type
	public static func decomposeCBORSignupResponse(data: Data) -> [(docType: String, jsonData: Data)]? {
		guard let sr = data.decodeJSON(type: SignUpResponse.self), let drs = decomposeCBORDeviceResponse(data: data) else { return nil }
		return drs.compactMap {
			let response = Data(CBOR.encode($0.dr.toCBOR(options: CBOROptions()))).base64EncodedString()
			var jsonObj = ["response": response]
			if let pk = sr.privateKey { jsonObj["privateKey"] = pk }
			guard let jsonData = try? JSONSerialization.data(withJSONObject: jsonObj) else { return nil }
			return (docType: $0.docType, jsonData: jsonData)
		}
	}
	
	func loadDocuments() {
		guard let docs = try? storageService.loadDocuments() else { return }
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
		refreshStatistics()
	}
	
	public func getKnownDoc<T>(of: T.Type) -> T? where T: MdocDecodable {
		mdocModels.first(where: { $0 != nil && type(of: $0!) == of}) as? T
	}
	
	public func getDoc(i: Int) -> MdocDecodable? {
		guard i < mdocModels.count else { return nil }
		return mdocModels[i]
	}
	
	public func removeDoc(i: Int) {
		guard i < modelIds.count, let id = modelIds[i] else { return }
		try? storageService.deleteDocument(id: id)
		modelIds[i] = nil; mdocModels[i] = nil; docTypes[i] = nil
		refreshStatistics()
	}


}
