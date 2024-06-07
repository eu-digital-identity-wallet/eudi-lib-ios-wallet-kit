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
import MdocSecurity18013
import MdocDataTransfer18013
import WalletStorage
import LocalAuthentication
import CryptoKit
import OpenID4VCI
import SwiftCBOR

/// User wallet implementation
public final class EudiWallet: ObservableObject {
	/// Storage manager instance
	public private(set) var storage: StorageManager
	var storageService: any WalletStorage.DataStorageService { storage.storageService }
	/// Instance of the wallet initialized with default parameters
	public static private(set) var standard: EudiWallet = EudiWallet()
	/// Whether user authentication via biometrics or passcode is required before sending user data
	public var userAuthenticationRequired: Bool
	/// Trusted root certificates to validate the reader authentication certificate included in the proximity request
	public var trustedReaderCertificates: [Data]?
	/// Method to perform mdoc authentication (MAC or signature). Defaults to device MAC
	public var deviceAuthMethod: DeviceAuthMethod = .deviceMac
	/// OpenID4VP verifier api URL (used for preregistered clients)
	public var verifierApiUri: String?
	/// OpenID4VP verifier legal name (used for preregistered clients)
	public var verifierLegalName: String?
	/// OpenID4VCI issuer url
	public var openID4VciIssuerUrl: String?
	/// OpenID4VCI client id
	public var openID4VciClientId: String?
	/// OpenID4VCI redirect URI. Defaults to "eudi-openid4ci://authorize/"
	public var openID4VciRedirectUri: String = "eudi-openid4ci://authorize"
	/// Use iPhone Secure Enclave to protect keys and perform cryptographic operations. Defaults to true (if available)
	public var useSecureEnclave: Bool { didSet { if !SecureEnclave.isAvailable { useSecureEnclave = false } } }
	
	/// Initialize a wallet instance. All parameters are optional.
	public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, verifierApiUri: String? = nil, openID4VciIssuerUrl: String? = nil, openID4VciClientId: String? = nil, openID4VciRedirectUri: String? = nil) {
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		let storageService = switch storageType { case .keyChain:keyChainObj }
		storage = StorageManager(storageService: storageService)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
		#if DEBUG
		self.userAuthenticationRequired = false
		#endif
		self.verifierApiUri	= verifierApiUri
		self.openID4VciIssuerUrl = openID4VciIssuerUrl
		self.openID4VciClientId = openID4VciClientId
		if let openID4VciRedirectUri { self.openID4VciRedirectUri = openID4VciRedirectUri }
		useSecureEnclave = SecureEnclave.isAvailable
	}
	
	/// Prepare issuing
	/// - Parameters:
	///   - docType: document type
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: (Issue request key pair, vci service, unique id)
	func prepareIssuing(docType: String?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
		guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
		guard let openID4VciClientId else { throw WalletError(description: "clientId not defined")}
		let id: String = UUID().uuidString
		let issueReq = try await Self.authorizedAction(action: {
			return try await beginIssueDocument(id: id, privateKeyType: useSecureEnclave ? .secureEnclaveP256 : .x963EncodedP256, saveToStorage: false)
		}, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(docType ?? "", comment: "")))
		guard let issueReq else { throw LAError(.userCancel)}
		let openId4VCIService = OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, clientId: openID4VciClientId, callbackScheme: openID4VciRedirectUri)
		return (issueReq, openId4VCIService, id)
	}
	
	/// Issue a document with the given docType using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	///  - Parameters:
	///   - docType: Document type
	///   - format: Optional format type. Defaults to cbor
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: The document issued. It is saved in storage.
	@discardableResult public func issueDocument(docType: String, format: DataFormat = .cbor, promptMessage: String? = nil) async throws -> WalletStorage.Document {
		let (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: docType, promptMessage: promptMessage)
		let data = try await openId4VCIService.issueDocument(docType: docType, format: format, useSecureEnclave: useSecureEnclave)
		return try await finalizeIssuing(id: id, data: data, docType: docType, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService)
	}
	
	func finalizeIssuing(id: String, data: Data, docType: String?, format: DataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService) async throws -> WalletStorage.Document  {
		let iss = IssuerSigned(data: [UInt8](data))
		let deviceResponse = iss != nil ? nil : DeviceResponse(data: [UInt8](data))
		guard let ddt = DocDataType(rawValue: format.rawValue) else { throw WalletError(description: "Invalid format \(format.rawValue)") }
		let docTypeToSave = docType ?? (format == .cbor ? iss?.issuerAuth.mso.docType ?? deviceResponse?.documents?.first?.docType : nil)
		var dataToSave: Data? = data
		if let deviceResponse {
			if let iss = deviceResponse.documents?.first?.issuerSigned { dataToSave = Data(iss.encode(options: CBOROptions())) } else { dataToSave = nil }
		}
		guard let docTypeToSave else { throw WalletError(description: "Unknown document type") }
		guard let dataToSave else { throw WalletError(description: "Issued data cannot be recognized") }
		var issued: WalletStorage.Document
		if !openId4VCIService.usedSecureEnclave {
			issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .x963EncodedP256, privateKey: issueReq.keyData, createdAt: Date())
		} else {
			issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .secureEnclaveP256, privateKey: issueReq.keyData, createdAt: Date())
		}
		try issueReq.saveToStorage(storage.storageService)
		try endIssueDocument(issued)
		await storage.appendDocModel(issued)
		await storage.refreshPublishedVars()
		return issued
	}
	
	/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached
	/// - Parameters:
	///   - uriOffer: url with offer
	///   - format: data format
	///   - useSecureEnclave: whether to use secure enclave (if supported)
	/// - Returns: Offered document info model
	public func resolveOfferUrlDocTypes(uriOffer: String, format: DataFormat = .cbor, useSecureEnclave: Bool = true) async throws -> [OfferedDocModel] {
		let (_, openId4VCIService, _) = try await prepareIssuing(docType: nil)
		return try await openId4VCIService.resolveOfferDocTypes(uriOffer: uriOffer, format: format)
	}
	
	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: doc types to be issued
	///   - format: data format
	///   - promptMessage: prompt message for biometric authentication (optional)
	///   - useSecureEnclave: whether to use secure enclave (if supported)
	///   - claimSet: claim set (optional)
	/// - Returns: Array of issued and stored documents
	public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], format: DataFormat = .cbor, promptMessage: String? = nil, useSecureEnclave: Bool = true, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] {
		guard format == .cbor else { throw fatalError("jwt format not implemented") }
		var (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: docTypes.map(\.docType).joined(separator: ", "), promptMessage: promptMessage)
		let docsData = try await openId4VCIService.issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes, format: format, useSecureEnclave: useSecureEnclave, claimSet: claimSet)
		var documents = [WalletStorage.Document]()
		for (i, docData) in docsData.enumerated() {
			if i > 0 { (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: nil) }
			openId4VCIService.usedSecureEnclave = useSecureEnclave && SecureEnclave.isAvailable
			documents.append(try await finalizeIssuing(id: id, data: docData, docType: nil, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService))
		}
		return documents
	}
	/// Begin issuing a document by generating an issue request
	///
	/// - Parameters:
	///   - id: Document identifier
	///   - issuer: Issuer function
	public func beginIssueDocument(id: String, privateKeyType: PrivateKeyType = .secureEnclaveP256, saveToStorage: Bool = true) async throws -> IssueRequest {
		let request = try IssueRequest(id: id, privateKeyType: privateKeyType)
		if saveToStorage { try request.saveToStorage(storage.storageService) }
		return request
	}
	
	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document) throws {
		try storage.storageService.saveDocumentData(issued, dataToSaveType: .doc, dataType: issued.docDataType.rawValue, allowOverwrite: true)
		try storage.storageService.saveDocumentData(issued, dataToSaveType: .key, dataType: issued.privateKeyType!.rawValue, allowOverwrite: true)
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
	public func deleteDocuments() async throws  {
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
			.map { Document(docType: $0.docType, docDataType: .cbor, data: $0.issData, privateKeyType: .x963EncodedP256, privateKey: $0.pkData, createdAt: Date.distantPast, modifiedAt: nil) }
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
	
	/// Prepare Service Data Parameters
	/// - Parameters:
	///   - docType: docType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A data dictionary that can be used to initialize a presentation service
	public func prepareServiceDataParameters(docType: String? = nil, dataFormat: DataFormat = .cbor ) throws -> [String : Any] {
		var parameters: [String: Any]
		switch dataFormat {
		case .cbor:
			guard var docs = try storageService.loadDocuments(), docs.count > 0 else { throw WalletError(description: "No documents found") }
			if let docType { docs = docs.filter { $0.docType == docType} }
			if let docType { guard docs.count > 0 else { throw WalletError(description: "No documents of type \(docType) found") } }
			let cborsWithKeys = docs.compactMap { $0.getCborData() }
			guard cborsWithKeys.count > 0 else { throw WalletError(description: "Documents decode error") }
			parameters = [InitializeKeys.document_signup_issuer_signed_obj.rawValue: Dictionary(uniqueKeysWithValues: cborsWithKeys.map(\.iss)), InitializeKeys.device_private_key_obj.rawValue: Dictionary(uniqueKeysWithValues: cborsWithKeys.map(\.dpk))]
			if let trustedReaderCertificates { parameters[InitializeKeys.trusted_certificates.rawValue] = trustedReaderCertificates }
			parameters[InitializeKeys.device_auth_method.rawValue] = deviceAuthMethod.rawValue
		default:
			fatalError("jwt format not implemented")
		}
		return parameters
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - docType: DocType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(flow: FlowType, docType: String? = nil, dataFormat: DataFormat = .cbor) -> PresentationSession {
		do {
			let parameters = try prepareServiceDataParameters(docType: docType, dataFormat: dataFormat)
			let docIdAndTypes = storage.getDocIdsToTypes()
			switch flow {
			case .ble:
				let bleSvc = try BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc, docIdAndTypes: docIdAndTypes, userAuthenticationRequired: userAuthenticationRequired)
			case .openid4vp(let qrCode):
				let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode, openId4VpVerifierApiUri: self.verifierApiUri, openId4VpVerifierLegalName: self.verifierLegalName)
				return PresentationSession(presentationService: openIdSvc, docIdAndTypes: docIdAndTypes, userAuthenticationRequired: userAuthenticationRequired)
			default:
				return PresentationSession(presentationService: FaultPresentationService(error: PresentationSession.makeError(str: "Use beginPresentation(service:)")), docIdAndTypes: docIdAndTypes, userAuthenticationRequired: false)
			}
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error), docIdAndTypes: [:], userAuthenticationRequired: false)
		}
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - service: A ``PresentationService`` instance
	///   - docType: DocType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(service: any PresentationService) -> PresentationSession {
		PresentationSession(presentationService: service, docIdAndTypes: storage.getDocIdsToTypes(), userAuthenticationRequired: userAuthenticationRequired)
	}
	
	@MainActor
	/// Perform an action after user authorization via TouchID/FaceID/Passcode
	/// - Parameters:
	///   - dismiss: Action to perform if the user cancels authorization
	///   - action: Action to perform after user authorization
	public static func authorizedAction<T>(action: () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		return try await authorizedAction(isFallBack: false, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
	}
	
	/// Wrap an action with TouchID or FaceID authentication
	/// - Parameters:
	///   - isFallBack: true if fallback (ask for pin code)
	///   - dismiss: action to dismiss current page
	///   - action: action to perform after authentication
	static func authorizedAction<T>(isFallBack: Bool = false, action: () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		guard !disabled else {
			return try await action()
		}
		let context = LAContext()
		var error: NSError?
		let policy: LAPolicy = .deviceOwnerAuthentication
		if context.canEvaluatePolicy(policy, error: &error) {
			do {
				let success = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
				if success {
					return try await action()
				}
				else { dismiss()}
			} catch let laError as LAError {
				if !isFallBack, laError.code == .userFallback {
					return try await authorizedAction(isFallBack: true, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
				} else {
					dismiss()
					return nil
				}
			}
		} else if let error {
			throw WalletError(description: error.localizedDescription, code: error.code)
		}
		return nil
	}
}
