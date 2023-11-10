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
import LocalAuthentication

/// User wallet implementation
public final class EudiWallet: ObservableObject {
	public private(set) var storageService: any DataStorageService
	public var documentsViewModel: DocumentsViewModel
	public static private(set) var standard: EudiWallet = EudiWallet()
	public var userAuthenticationRequired: Bool
	public var trustedReaderCertificates: [Data]?
	
	init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true) {
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		self.storageService = switch storageType { case .keyChain:keyChainObj }
		documentsViewModel = DocumentsViewModel(storageService: keyChainObj)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
	}
	
	public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> WalletStorage.Document) async throws {
		let request = try IssueRequest()
		let document = try await issuer(request)
		try self.storageService.saveDocument(document)
	}
	
	public func loadSampleData(sampleDataFiles: [String]? = nil) throws {
		try? storageService.deleteDocuments()
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
				guard let docs = try storageService.loadDocuments(), let doc = docs.first else { throw WalletError(description: "No documents found") }
				guard let sr = doc.data.decodeJSON(type: SignUpResponse.self), let dr = sr.deviceResponse, let dpk = sr.devicePrivateKey else { throw WalletError(description: "Error in document data") }
				parameters = [InitializeKeys.document_signup_response_data.rawValue: [dr], InitializeKeys.device_private_key.rawValue: dpk]
				if let trustedReaderCertificates { parameters[InitializeKeys.trusted_certificates.rawValue] = trustedReaderCertificates }
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
	
	@MainActor
	public static func authorizedAction(isFallBack: Bool = false, dismiss: () -> Void, action: () async throws -> Void) async throws {
		let context = LAContext()
		var error: NSError?
		let policy: LAPolicy = .deviceOwnerAuthentication
		if context.canEvaluatePolicy(policy, error: &error) {
			do {
				let success = try await context.evaluatePolicy(policy, localizedReason: NSLocalizedString("authenticate_to_share_data", comment: ""))
				if success {
					try await action()
				}
				else { dismiss()}
			} catch let laError as LAError {
				if !isFallBack, laError.code == .userFallback {
					try await authorizedAction(isFallBack: true, dismiss: dismiss, action: action)
				} else { dismiss() }
			}
		} else if let error {
			throw WalletError(description: error.localizedDescription, code: error.code)
		}
	}
}
