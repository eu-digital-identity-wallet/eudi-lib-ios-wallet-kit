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
	public private(set) var storage: StorageModel
	var storageService: any WalletStorage.DataStorageService { storage.storageService }
	
	public static private(set) var standard: EudiWallet = EudiWallet()
	public var userAuthenticationRequired: Bool
	public var trustedReaderCertificates: [Data]?
	
	init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true) {
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		let storageService = switch storageType { case .keyChain:keyChainObj }
		storage = StorageModel(storageService: storageService)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
	}
	
	public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> WalletStorage.Document) async throws {
		let request = try IssueRequest()
		let document = try await issuer(request)
		try storage.storageService.saveDocument(document)
	}
	
	public func loadSampleData(sampleDataFiles: [String]? = nil) throws {
		try? storageService.deleteDocuments()
		let docSamples = (sampleDataFiles ?? ["EUDI_sample_data"]).compactMap { Data(name:$0) }
			.compactMap(StorageModel.decomposeCBORSignupResponse(data:)).flatMap {$0}
			.map {  Document(docType: $0.docType, data: $0.jsonData, createdAt: Date.distantPast, modifiedAt: nil) }
		for docSample in docSamples { try storageService.saveDocument(docSample) }
		storage.loadDocuments()
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(flow: FlowType, docType: String? = nil, dataFormat: DataFormat = .cbor) -> PresentationSession {
		var parameters: [String: Any]
		do {
			switch dataFormat {
			case .cbor:
				guard var docs = try storageService.loadDocuments(), docs.count > 0 else { throw WalletError(description: "No documents found") }
				if let docType { docs = docs.filter { $0.docType == docType} }
				if let docType { guard docs.count > 0 else { throw WalletError(description: "No documents of type \(docType) found") } }
				let srs = docs.compactMap {$0.data.decodeJSON(type: SignUpResponse.self)}; let drs = srs.compactMap(\.deviceResponse)
				guard drs.count > 0 else { throw WalletError(description: "Documents decode error") }
				guard let sr = srs.first, let dpk = sr.devicePrivateKey else { throw WalletError(description: "Error: No private key found") }
				parameters = [InitializeKeys.document_signup_response_data.rawValue: drs, InitializeKeys.device_private_key.rawValue: dpk]
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
