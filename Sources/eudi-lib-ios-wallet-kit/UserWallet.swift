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

/// User wallet implementation
public class UserWallet: ObservableObject {
	public var storageService: any DataStorageService
	
	public init(storageType: StorageType = .keyChain) {
		let keyChain = KeyChainStorageService()
		self.storageService = switch storageType { case .sample: DataSampleStorageService(storageService: keyChain); default: keyChain }
	}
	
	public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> Document) async throws {
		let request = try IssueRequest()
		var document = try await issuer(request)
		try self.storageService.saveDocument(document)
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
				let doc = try storageService.loadDocument(id: type(of: storageService).defaultId)
				guard let sr = doc.data.decodeJSON(type: SignUpResponse.self), let dr = sr.deviceResponse, let dpk = sr.devicePrivateKey else { throw NSError(domain: "\(UserWallet.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: "Error in document data"]) }
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
