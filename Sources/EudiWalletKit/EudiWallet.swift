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
import Logging
import FileLogging

/// User wallet implementation
public final class EudiWallet: ObservableObject {
	/// Storage manager instance
	public private(set) var storage: StorageManager
	var storageService: any WalletStorage.DataStorageService { storage.storageService }
	/// Instance of the wallet initialized with default parameters
	public static private(set) var standard: EudiWallet = try! EudiWallet()
	/// The [service](https://developer.apple.com/documentation/security/ksecattrservice) used to store documents. Use a different service than the default one if you want to store documents in a different location.
	public var serviceName: String { didSet { storage.storageService.serviceName = serviceName } }
	/// The [access group](https://developer.apple.com/documentation/security/ksecattraccessgroup) that documents are stored in.
	public var accessGroup: String? { didSet { storage.storageService.accessGroup = accessGroup } } 
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
	/// OpenID4VCI issuer URL
	public var openID4VciIssuerUrl: String?
	/// OpenID4VCI issuer parameters
	public var openID4VciConfig: OpenId4VCIConfig?
	/// Use iPhone Secure Enclave to protect keys and perform cryptographic operations. Defaults to true (if available)
	public var useSecureEnclave: Bool { didSet { if !SecureEnclave.isAvailable { useSecureEnclave = false } } }
	/// Optional model factory type to create custom stronly-typed models
	public var modelFactory: (any MdocModelFactory.Type)? { didSet { storage.modelFactory = modelFactory } } 
	/// This variable can be used to set a custom URLSession for network requests.
	public var urlSession: URLSession
	/// If not-nil, logging to the specified log file name will be configured
	public var logFileName: String? { didSet { try? initializeLogging() } }
	public static var defaultClientId = "wallet-dev"
	public static var defaultOpenID4VciRedirectUri = URL(string: "eudi-openid4ci://authorize")!
	public static var defaultServiceName = "eudiw"
	/// Initialize a wallet instance. All parameters are optional.
	public init(storageType: StorageType = .keyChain, serviceName: String = defaultServiceName, accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, verifierApiUri: String? = nil, openID4VciIssuerUrl: String? = nil, openID4VciConfig: OpenId4VCIConfig? = nil, urlSession: URLSession? = nil, logFileName: String? = nil, modelFactory: (any MdocModelFactory.Type)? = nil) throws {
		guard !serviceName.isEmpty, !serviceName.contains(":") else { throw WalletError(description: "Not allowed service name, remove : character") }
		self.serviceName = serviceName
		self.accessGroup = accessGroup
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		let storageService = switch storageType { case .keyChain:keyChainObj }
		storage = StorageManager(storageService: storageService, modelFactory: modelFactory)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
		#if DEBUG
		self.userAuthenticationRequired = false
		#endif
		self.verifierApiUri	= verifierApiUri
		self.openID4VciIssuerUrl = openID4VciIssuerUrl
		self.openID4VciConfig = openID4VciConfig
		self.urlSession = urlSession ?? URLSession.shared
		self.logFileName = logFileName
		useSecureEnclave = SecureEnclave.isAvailable
	}
	
	/// Helper method to return a file URL from a file name.
	///
	/// The file is created in the caches directory
	/// - Parameter fileName: A file name
	/// - Returns: Th URL of a log file stored in the caches directory
	public static func getLogFileURL(_ fileName: String) throws -> URL? {
		return try FileManager.getCachesDirectory().appendingPathComponent(fileName)
	}
	
	/// Get the contents of a log file stored in the caches directory
	/// - Parameter fileName: A file name
	/// - Returns: The file contents
	public func getLogFileContents(_ fileName: String) throws -> String {
		let logFileURL = try Self.getLogFileURL(fileName)
		guard let logFileURL else { throw WalletError(description: "Cannot create URL for file name \(fileName)") }
		return try String(contentsOf: logFileURL, encoding: .utf8)
	}
	
	/// Reset a log file stored in the caches directory
	/// - Parameter fileName: A file name
	public func resetLogFile(_ fileName: String) throws {
		let logFileURL = try Self.getLogFileURL(fileName)
		guard let logFileURL else { throw WalletError(description: "Cannot create URL for file name \(fileName)") }
		try FileManager.default.removeItem(at: logFileURL)
	}
	
	private func initializeLogging() throws {
		LoggingSystem.bootstrap { [unowned self] label in
			var handlers:[LogHandler] = []
			if _isDebugAssertConfiguration() {
				handlers.append(StreamLogHandler.standardOutput(label: label))
			}
			if let logFileName {
				do {
					let logFileURL = try Self.getLogFileURL(logFileName)
					guard let logFileURL else { throw WalletError(description: "Cannot create URL for file name \(logFileName)") }
					let fileLogger = try FileLogging(to: logFileURL)
					handlers.append(FileLogHandler(label: label, fileLogger: fileLogger))
				} catch { fatalError("Logging setup failed: \(error.localizedDescription)") }
			}
			return MultiplexLogHandler(handlers)
		}
	}
	
	/// Prepare issuing
	/// - Parameters:
	///   - docType: document type
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: (Issue request key pair, vci service, unique id)
	func prepareIssuing(docType: String?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
		guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
		guard openID4VciConfig?.clientId != nil else { throw WalletError(description: "clientId not defined")}
		guard openID4VciConfig?.authFlowRedirectionURI != nil else { throw WalletError(description: "Auth flow Redirect URI not defined")}
		let id: String = UUID().uuidString
		let issueReq = try await Self.authorizedAction(action: {
			return try await beginIssueDocument(id: id, privateKeyType: useSecureEnclave ? .secureEnclaveP256 : .x963EncodedP256, saveToStorage: false)
		}, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(docType ?? "", comment: "")))
		guard let issueReq else { throw LAError(.userCancel)}
		let openId4VCIService = OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, config: openID4VciConfig ?? OpenId4VCIConfig(clientId: Self.defaultClientId, authFlowRedirectionURI: Self.defaultOpenID4VciRedirectUri), urlSession: urlSession)
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

	/// Request a deferred issuance based on a stored deferred document. On success, the deferred document is updated with the issued document.
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameter deferredDoc: A stored document with deferred status
	/// - Returns: The issued document in case it was approved in the backend and the deferred data are valid, otherwise a deferred status document
	@discardableResult public func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> WalletStorage.Document {
		guard deferredDoc.status == .deferred else { throw WalletError(description: "Invalid document status") }
		guard let pkt = deferredDoc.privateKeyType, let pk = deferredDoc.privateKey, let format = DataFormat(deferredDoc.docDataType) else { throw WalletError(description: "Invalid document") }
		let issueReq = try IssueRequest(id: deferredDoc.id, docType: deferredDoc.docType, privateKeyType: pkt, keyData: pk)
		let openId4VCIService = OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: "", config: self.openID4VciConfig ?? OpenId4VCIConfig(clientId: Self.defaultClientId, authFlowRedirectionURI: Self.defaultOpenID4VciRedirectUri), urlSession: urlSession)
		openId4VCIService.usedSecureEnclave = deferredDoc.privateKeyType == .secureEnclaveP256
		let data = try await openId4VCIService.requestDeferredIssuance(deferredDoc: deferredDoc)
		guard case .issued(_, _) = data else { return deferredDoc }
		return try await finalizeIssuing(id: deferredDoc.id, data: data, docType: deferredDoc.docType, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService)
	}
	
	func finalizeIssuing(id: String, data: IssuanceOutcome, docType: String?, format: DataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService) async throws -> WalletStorage.Document  {
		var dataToSave: Data
		var docTypeToSave: String
		var displayName: String?
		guard let ddt = DocDataType(rawValue: format.rawValue) else { throw WalletError(description: "Invalid format \(format.rawValue)") }
		switch data {
		case .issued(let data, let dn):
			dataToSave = data
			displayName = dn
			let dt = if format == .cbor { IssuerSigned(data: [UInt8](data))?.issuerAuth.mso.docType ?? docType } else { docType }
			guard let dt else { throw WalletError(description: "Unknown document type") }
			docTypeToSave = dt
		case .deferred(let deferredIssuanceModel):
			dataToSave = try JSONEncoder().encode(deferredIssuanceModel)
			docTypeToSave = docType ?? "DEFERRED"
			displayName = deferredIssuanceModel.displayName
		}
		var newDocument: WalletStorage.Document
		let newDocStatus: WalletStorage.DocumentStatus = data.isDeferred ? .deferred : .issued
		if !openId4VCIService.usedSecureEnclave {
			newDocument = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .x963EncodedP256, privateKey: issueReq.keyData, createdAt: Date(), displayName: displayName,  status: newDocStatus)
		} else {
			newDocument = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .secureEnclaveP256, privateKey: issueReq.keyData, createdAt: Date(), displayName: displayName, status: newDocStatus)
		}
		try issueReq.saveToStorage(storage.storageService, status: newDocStatus)
		try endIssueDocument(newDocument)
		await storage.appendDocModel(newDocument)
		await storage.refreshPublishedVars()
		if !data.isDeferred, storage.deferredDocuments.first(where: { $0.id == id }) != nil {
			try await storage.deleteDocument(id: id, status: .deferred)
		}
		return newDocument
	}
	
	/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached
	/// - Parameters:
	///   - uriOffer: url with offer
	///   - format: data format
	///   - useSecureEnclave: whether to use secure enclave (if supported)
	/// - Returns: Offered issue information model
	public func resolveOfferUrlDocTypes(uriOffer: String, format: DataFormat = .cbor, useSecureEnclave: Bool = true) async throws -> OfferedIssuanceModel {
		let (_, openId4VCIService, _) = try await prepareIssuing(docType: nil)
		return try await openId4VCIService.resolveOfferDocTypes(uriOffer: uriOffer, format: format)
	}
	
	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: doc types to be issued
	///   - txCodeValue: Transaction code given to user
	///   - format: data format
	///   - promptMessage: prompt message for biometric authentication (optional)
	///   - useSecureEnclave: whether to use secure enclave (if supported)
	///   - claimSet: claim set (optional)
	/// - Returns: Array of issued and stored documents
	public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String? = nil, format: DataFormat = .cbor, promptMessage: String? = nil, useSecureEnclave: Bool = true, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] {
		guard format == .cbor else { fatalError("jwt format not implemented") }
		var (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: docTypes.map(\.docType).joined(separator: ", "), promptMessage: promptMessage)
		let docsData = try await openId4VCIService.issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes, txCodeValue: txCodeValue, format: format, useSecureEnclave: useSecureEnclave, claimSet: claimSet)
		var documents = [WalletStorage.Document]()
		for (i, docData) in docsData.enumerated() {
			if i > 0 { (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: nil) }
			openId4VCIService.usedSecureEnclave = useSecureEnclave && SecureEnclave.isAvailable
			documents.append(try await finalizeIssuing(id: id, data: docData, docType: docData.isDeferred ? docTypes[i].docType : nil, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService))
		}
		return documents
	}
	
	/// Begin issuing a document by generating an issue request
	///
	/// - Parameters:
	///   - id: Document identifier
	///   - issuer: Issuer function
	public func beginIssueDocument(id: String, privateKeyType: PrivateKeyType = .secureEnclaveP256, saveToStorage: Bool = true, bDeferred: Bool = false) async throws -> IssueRequest {
		let request = try IssueRequest(id: id, privateKeyType: privateKeyType)
		if saveToStorage { try request.saveToStorage(storage.storageService, status: bDeferred ? .deferred : .issued) }
		return request
	}
	
	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document) throws {
		try storage.storageService.saveDocument(issued, allowOverwrite: true) 
	}
	
	/// Load documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus = .issued) async throws -> [WalletStorage.Document]? {
		return try await storage.loadDocuments(status: status)
	}

	
	/// Delete all documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	public func deleteDocuments(status: WalletStorage.DocumentStatus = .issued) async throws  {
		return try await storage.deleteDocuments(status: status)
	}
	
	/// Load sample data from json files
	///
	/// The mdoc data are stored in wallet storage as documents
	/// - Parameter sampleDataFiles: Names of sample files provided in the app bundle
	public func loadSampleData(sampleDataFiles: [String]? = nil) async throws {
		try? storageService.deleteDocuments(status: .issued)
		let docSamples = (sampleDataFiles ?? ["EUDI_sample_data"]).compactMap { Data(name:$0) }
			.compactMap(SignUpResponse.decomposeCBORSignupResponse(data:)).flatMap {$0}
			.map { Document(docType: $0.docType, docDataType: .cbor, data: $0.issData, privateKeyType: .x963EncodedP256, privateKey: $0.pkData, createdAt: Date.distantPast, modifiedAt: nil, displayName: $0.docType == EuPidModel.euPidDocType ? "PID" : ($0.docType == IsoMdlModel.isoDocType ? "mDL" : $0.docType), status: .issued) }
		do {
			for docSample in docSamples {
				try storageService.saveDocument(docSample, allowOverwrite: true)
			}
			try await storage.loadDocuments(status: .issued)
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
	public func prepareServiceDataParameters(docType: String? = nil, dataFormat: DataFormat = .cbor ) throws -> [String: Any] {
		var parameters: [String: Any]
		switch dataFormat {
		case .cbor:
			guard var docs = try storageService.loadDocuments(status: .issued), docs.count > 0 else { throw WalletError(description: "No documents found") }
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
				let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode, openId4VpVerifierApiUri: self.verifierApiUri, openId4VpVerifierLegalName: self.verifierLegalName, urlSession: urlSession)
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
