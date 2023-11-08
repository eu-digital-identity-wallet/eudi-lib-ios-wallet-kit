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
import MdocDataTransfer18013
import WalletStorage

/// User wallet implementation
@dynamicMemberLookup
public class EudiWallet: ObservableObject {
	var storageService: any DataStorageService
	public var documentsViewModel: DocumentsViewModel
	
	public init(storageType: StorageType = .keyChain) {
		let keyChainObj = KeyChainStorageService()
		self.storageService = switch storageType { case .keyChain:keyChainObj }
		documentsViewModel = DocumentsViewModel(storageService: keyChainObj)
	}
	
	public subscript<T>(dynamicMember keyPath: KeyPath<DataStorageService, T>) -> T {
		storageService[keyPath: keyPath]
	}
	
	public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> WalletStorage.Document) async throws {
		let request = try IssueRequest()
		let document = try await issuer(request)
		try self.storageService.saveDocument(document)
	}
	
	public func loadSampleData(sampleDataFiles: [String]? = nil) throws {
		for (i,docType) in DocumentsViewModel.knownDocTypes.enumerated() {
			let sampleDataFile = if let sampleDataFiles { sampleDataFiles[i] } else { "EUDI_sample_data" }
			let docSample = Document(docType: docType, data: Data(name: sampleDataFile) ?? Data(), createdAt: Date.distantPast, modifiedAt: nil)
			try storageService.saveDocument(docSample)
		}
		documentsViewModel.loadDocuments()
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(flow: FlowType, dataFormat: DataFormat = .cbor) -> PresentationSession {
		var parameters: [String: Any]
		do {
			switch dataFormat {
			case .cbor:
				guard let docs = try storageService.loadDocuments(), let doc = docs.first else { throw NSError(domain: "\(EudiWallet.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: "No documents found"]) }
				guard let sr = doc.data.decodeJSON(type: SignUpResponse.self), let dr = sr.deviceResponse, let dpk = sr.devicePrivateKey else { throw NSError(domain: "\(EudiWallet.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: "Error in document data"]) }
				parameters = [InitializeKeys.document_signup_response_data.rawValue: [dr],
							  InitializeKeys.device_private_key.rawValue: dpk,
							  InitializeKeys.trusted_certificates.rawValue: [Data(name: "scytales_root_ca", ext: "der")!]
				]
			default:
				fatalError("jwt format not implemented")
			}
			switch flow {
			case .ble:
				let bleSvc = try BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc)
			case .openid4vp(let qrCode):
				let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode)
				return PresentationSession(presentationService: openIdSvc)
			}
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error))
		}
	}
}
