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
	public private(set) var storage: StorageManager
	var storageService: any WalletStorage.DataStorageService { storage.storageService }
	/// Instance of the wallet initialized with default parameters
	public static private(set) var standard: EudiWallet = EudiWallet()
	/// Whether user authentication via biometrics or passcode is required before sending user data
	public var userAuthenticationRequired: Bool
	/// Trusted root certificates to validate the reader authentication certificate included in the proximity request
	public var trustedReaderCertificates: [Data]?
	/// OpenID4VP verifier api URL (used for preregistered clients)
	public var openId4VpVerifierApiUri: String?
	
	public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true) {
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		let storageService = switch storageType { case .keyChain:keyChainObj }
		storage = StorageManager(storageService: storageService)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
	}
		
	/// Issue a document and save in wallet storage
	///
	///  ** Not tested **
	/// - Parameters:
	///   - id: Document identifier
	///   - issuer: Issuer function
	public func beginIssueDocument(id: String) async throws -> IssueRequest {
		let request = try IssueRequest(id: id)
		try request.saveToStorage(storage.storageService)
		return request
	}
	
	public func endIssueDocument(_ issued: WalletStorage.Document) throws {
		try storage.storageService.saveDocumentData(issued, dataToSaveType: .doc, dataType: issued.docDataType.rawValue, allowOverwrite: true)
	}
	
	/// Load documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]? {
		return try await storage.loadDocuments()
	}

	/// Delete all documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func deleteDocuments() async throws  {
		return try await storage.deleteDocuments()
	}
	
	/// Load sample data from json files
	///
	/// The mdoc data are stored in wallet storage as documents
	/// - Parameter sampleDataFiles: Names of sample files provided in the app bundle
	public func loadSampleData(sampleDataFiles: [String]? = nil) async throws {
		try? storageService.deleteDocuments()
		let docSamples = (sampleDataFiles ?? ["EUDI_sample_data"]).compactMap { Data(name:$0) }
			.compactMap(SignUpResponse.decomposeCBORSignupResponse(data:)).flatMap {$0}
			.map { Document(docType: $0.docType, docDataType: .cbor, data: $0.drData, privateKeyType: .x963EncodedP256, privateKey: $0.pkData, createdAt: Date.distantPast, modifiedAt: nil) }
		do {
		for docSample in docSamples {
			try storageService.saveDocument(docSample, allowOverwrite: true)
		}
		try await storage.loadDocuments()
		} catch {
			await storage.setError(error)
			throw WalletError(description: error.localizedDescription, code: (error as NSError).code)
		}
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - docType: DocType of documents to present (optional)
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
				let cborsWithKeys = docs.compactMap { $0.getCborData() }
				guard cborsWithKeys.count > 0 else { throw WalletError(description: "Documents decode error") }
				parameters = [InitializeKeys.document_signup_response_obj.rawValue: cborsWithKeys.map(\.dr), InitializeKeys.device_private_key_obj.rawValue: cborsWithKeys.first!.dpk]
				if let trustedReaderCertificates { parameters[InitializeKeys.trusted_certificates.rawValue] = trustedReaderCertificates }
			default:
				fatalError("jwt format not implemented")
			}
			switch flow {
			case .ble:
				let bleSvc = try BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc)
			case .openid4vp(let qrCode):
				let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode, openId4VpVerifierApiUri: self.openId4VpVerifierApiUri)
				return PresentationSession(presentationService: openIdSvc)
			}
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error))
		}
	}
	
	@MainActor
	/// Perform an action after user authorization via TouchID/FaceID/Passcode
	/// - Parameters:
	///   - dismiss: Action to perform if the user cancels authorization
	///   - action: Action to perform after user authorization
	public static func authorizedAction(dismiss: () -> Void, action: () async throws -> Void) async throws {
		try await authorizedAction(isFallBack: false, dismiss: dismiss, action: action)
	}
	
	static func authorizedAction(isFallBack: Bool = false, dismiss: () -> Void, action: () async throws -> Void) async throws {
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
