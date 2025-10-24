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
import StatiumSwift
import SwiftCBOR
import Logging
// ios specific imports
#if canImport(UIKit)
import FileLogging
import UIKit
#endif
import protocol OpenID4VCI.Networking
import OpenID4VCI
import eudi_lib_sdjwt_swift

/// User wallet implementation
public final class EudiWallet: ObservableObject, @unchecked Sendable {
	/// Storage manager instance
	public private(set) var storage: StorageManager!
	public private(set) var serviceName: String
	/// The [access group](https://developer.apple.com/documentation/security/ksecattraccessgroup) that documents are stored in.
	public private(set) var accessGroup: String?
	/// Optional model factory type to create custom stronly-typed models
	public private(set) var modelFactory: (any DocClaimsDecodableFactory)?
	/// Whether user authentication via biometrics or passcode is required before sending user data
	public var userAuthenticationRequired: Bool
	/// Trusted root certificates to validate the reader authentication certificate included in the proximity request
	public var trustedReaderCertificates: [Data]?
	/// Method to perform mdoc authentication (MAC or signature). Defaults to device MAC
	public var deviceAuthMethod: DeviceAuthMethod = .deviceMac
	/// preferred UI culture for localization of display names. It must be a 2-letter language code. If not set, the system locale is used
	public var uiCulture: String?
	public var openID4VpConfig: OpenId4VpConfiguration
	/// OpenID4VCI issuer parameters
	public private(set) var openID4VciConfigurations: [String: OpenId4VciConfiguration]?
	/// This variable can be used to set a custom networking client for network requests.
	let networkingVci: OpenID4VCINetworking
	let networkingVp: OpenID4VPNetworking

	/// If not-nil, logging to the specified log file name will be configured
	public var logFileName: String? { didSet { try? initializeLogging() } }
	/// transaction logger
	public var transactionLogger: (any TransactionLogger)?
	//public static let defaultOpenId4VCIConfig =
	public static let defaultServiceName = "eudiw"
	/// Initialize a wallet instance. All parameters are optional.
	/// - Parameters:
	///   - storageType: The type of storage to use. Defaults to `.keyChain`.
	///   - serviceName: The service name for the keychain. Optional.
	///   - accessGroup: The access group for the keychain. Optional.
	///   - trustedReaderCertificates: An array of trusted reader certificates. Optional.
	///   - userAuthenticationRequired: A boolean indicating if user authentication is required when issuing or presenting a document. Defaults to `true`.
	///   - openID4VpConfig: The configuration for OpenID4VP. Optional.
	///   - openID4VciConfigurations: A dictionary of OpenId4VciConfiguration objects keyed by an arbitrary issuer name. Optional.
	///   - networking: The networking Client to use for network requests. Optional.
	///   - logFileName: The name of the log file. Optional.
	///   - secureAreas: An array of secure areas. Optional.
	///   - modelFactory: The factory for creating Mdoc models. Optional.
	///
	/// - Throws: An error if initialization fails.
	///
	/// ```swift
	/// let wallet = try! EudiWallet(serviceName: "my_wallet_app", trustedReaderCertificates: [Data(name: "eudi_pid_issuer_ut", ext: "der")!])
	/// ```
	public init(storageService: (any DataStorageService)? = nil, serviceName: String? = nil, accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, openID4VpConfig: OpenId4VpConfiguration? = nil, openID4VciConfigurations: [String: OpenId4VciConfiguration]? = nil, networking: (any NetworkingProtocol)? = nil, logFileName: String? = nil, secureAreas: [any SecureArea]? = nil, transactionLogger: (any TransactionLogger)? = nil, modelFactory: (any DocClaimsDecodableFactory)? = nil) throws {

		try Self.validateServiceParams(serviceName: serviceName)
		self.serviceName = serviceName ?? Self.defaultServiceName
		self.accessGroup = accessGroup
		self.modelFactory = modelFactory
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
		#if DEBUG
		self.userAuthenticationRequired = false
		#endif
		self.openID4VpConfig = openID4VpConfig ?? OpenId4VpConfiguration()
		self.openID4VciConfigurations = openID4VciConfigurations
		self.networkingVci = OpenID4VCINetworking(networking: networking ?? URLSession.shared)
		self.networkingVp = OpenID4VPNetworking(networking: networking ?? URLSession.shared)
		self.logFileName = logFileName
		let storageServiceObj = storageService ?? KeyChainStorageService(serviceName: self.serviceName, accessGroup: self.accessGroup)
		storage = StorageManager(storageService: storageServiceObj, modelFactory: self.modelFactory)
		if let secureAreas, !secureAreas.isEmpty {
			for asa in secureAreas { SecureAreaRegistry.shared.register(secureArea: asa) }
		} else {
			// register default secure areas
			let kcSks = KeyChainSecureKeyStorage(serviceName: self.serviceName, accessGroup: accessGroup)
			if SecureEnclave.isAvailable { SecureAreaRegistry.shared.register(secureArea: SecureEnclaveSecureArea.create(storage: kcSks)) }
			SecureAreaRegistry.shared.register(secureArea: SoftwareSecureArea.create(storage: kcSks))
		}
		self.transactionLogger = transactionLogger
		if let openID4VciConfigurations { try registerOpenId4VciServices(openID4VciConfigurations) }
	}

	/// Helper method to return a file URL from a file name.
	///
	/// The file is created in the caches directory
	/// - Parameter fileName: A file name
	/// - Returns: Th URL of a log file stored in the caches directory
	nonisolated public static func getLogFileURL(_ fileName: String) throws -> URL? {
		return try FileManager.getCachesDirectory().appendingPathComponent(fileName)
	}

	private static func validateServiceParams(serviceName: String? = nil) throws {
		guard (serviceName?.contains(":") ?? false) == false else {
			let msg = "Not allowed service name, contains : character"
			logger.error("validateServiceParams:\(msg)")
			throw WalletError(description: msg)
		}
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
		LoggingSystem.bootstrap { [logFileName] label in
			var handlers:[LogHandler] = []
			if _isDebugAssertConfiguration() {
				handlers.append(StreamLogHandler.standardOutput(label: label))
			}
			#if canImport(UIKit)
				if let logFileName {
					do {
						let logFileURL = try Self.getLogFileURL(logFileName)
						guard let logFileURL else { throw WalletError(description: "Cannot create URL for file name \(logFileName)") }
						let fileLogger = try FileLogging(to: logFileURL)
						handlers.append(FileLogHandler(label: label, fileLogger: fileLogger))
					} catch { fatalError("Logging setup failed: \(error.localizedDescription)") }
				}
			#endif
			return MultiplexLogHandler(handlers)
		}
	}

	/// Register OpenID4VCI services for each configuration.
	/// - Parameter configurations: A dictionary of OpenId4VciConfiguration objects keyed by an arbitrary issuer name
	public func registerOpenId4VciServices(_ configurations: [String: OpenId4VciConfiguration]) throws {
		for (name, config) in configurations {
			try registerOpenId4VciService(name: name, config: config)
		}
	}
	/// Register an OpenId4VCI service with a given name and configuration.
	@discardableResult func registerOpenId4VciService(name: String, config: OpenId4VciConfiguration) throws -> OpenId4VCIService {
		let vciService = try OpenId4VCIService(uiCulture: uiCulture, config: config, networking: self.networkingVci, storage: storage, storageService: storage.storageService)
		OpenId4VCIServiceRegistry.shared.register(name: name, service: vciService)
		return vciService
	}

	/// Get issuer metadata using OpenId4VCI protocol
	/// - Parameter issuerName: The name of the issuer service
	/// - Returns: The issuer metadata
	public func getIssuerMetadata(issuerName: String) async throws -> CredentialIssuerMetadata {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.getIssuerMetadata()
	}

	/// Issue a document using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	///  - Parameters:
	///   - issuerName: The name of the issuer service
	///   - docTypeIdentifier: Document type identifier (msoMdoc, sdJwt, or configuration identifier)
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, defaults are fetched from issuer metadata. Use `getDefaultCredentialOptions(_:)` to retrieve issuer-recommended settings.
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: The document issued. It is saved in storage.
	@discardableResult public func issueDocument(issuerName: String, docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.issueDocument(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions, keyOptions: keyOptions, promptMessage: promptMessage)
	}

	/// Get default credential options (batch-size and credential policy) for a document type
	///
	/// Queries the issuer's metadata to retrieve recommended credential configuration. The returned `CredentialOptions` contains:
	/// - `batchSize`: Number of credentials to issue in a batch (enables multiple presentations before re-issuance)
	/// - `credentialPolicy`: Either `.oneTimeUse` (credential consumed after presentation) or `.rotateUse` (unlimited presentations)
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - docTypeIdentifier: Document type identifier (msoMdoc, sdJwt, or configuration identifier)
	/// - Returns: Issuer-recommended credential options
	public func getDefaultCredentialOptions(issuerName: String, docTypeIdentifier: DocTypeIdentifier) async throws -> CredentialOptions {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.getMetadataDefaultCredentialOptions(docTypeIdentifier)
	}

	/// Request a deferred issuance based on a stored deferred document. On success, the deferred document is replaced with the issued document.
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - deferredDoc: A stored document with deferred status
	///   - credentialOptions: Credential options specifying batch size and credential policy for the deferred document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the deferred data are valid, otherwise a deferred status document
	@discardableResult public func requestDeferredIssuance(issuerName: String, deferredDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.requestDeferredIssuance(deferredDoc: deferredDoc, credentialOptions: credentialOptions, keyOptions: keyOptions)
	}

	/// Resume pending issuance. Supports dynamic issuance scenario
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - pendingDoc: A temporary document with pending status
	///   - webUrl: The authorization URL returned from the presentation service (for dynamic issuance)
	///   - credentialOptions: Credential options specifying batch size and credential policy for the pending document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the pendingDoc data are valid, otherwise a pendingDoc status document
	@discardableResult public func resumePendingIssuance(issuerName: String, pendingDoc: WalletStorage.Document, webUrl: URL?, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.resumePendingIssuance(pendingDoc: pendingDoc, webUrl: webUrl, credentialOptions: credentialOptions, keyOptions: keyOptions)
	}

/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached
	/// When resolving an offer, defaultKeyOptions are now included
	/// - Parameters:
	///   - uriOffer: url with offer
	/// - Returns: Offered issue information model
	public func resolveOfferUrlDocTypes(offerUri: String) async throws -> OfferedIssuanceModel {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher<CredentialOfferRequestObject>(session: networkingVci), credentialIssuerMetadataResolver: OpenId4VCIService.makeMetadataResolver(networkingVci), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networkingVci), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networkingVci))).resolve(source: try .init(urlString: offerUri), policy: .ignoreSigned)
		switch result {
		case .success(let offer):
			let urlString = offer.credentialIssuerIdentifier.url.getBaseUrl()
			let credentialIssuerIdentifier = try CredentialIssuerId(urlString)
			var vciService = await OpenId4VCIServiceRegistry.shared.getByIssuerURL(issuerURL: credentialIssuerIdentifier.url.absoluteString)
			if vciService == nil {
				vciService = try registerOpenId4VciService(name: urlString, config: OpenId4VciConfiguration(credentialIssuerURL: credentialIssuerIdentifier.url.absoluteString))
			}
			return try await vciService!.resolveOfferUrlDocTypes(offerUri: offerUri)
		case .failure(let error):
			throw PresentationSession.makeError(str: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: offered doc models available to be issued. Contains key options (secure are name and other options)
	///   - txCodeValue: Transaction code given to user (if available)
	///   - promptMessage: prompt message for biometric authentication (optional)
	///  - configuration: Optional OpenId4VciConfiguration to override the default one for this issuance
	/// - Returns: Array of issued and stored documents
	public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String? = nil, promptMessage: String? = nil, configuration: OpenId4VciConfiguration? = nil) async throws -> [WalletStorage.Document] {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher<CredentialOfferRequestObject>(session: networkingVci), credentialIssuerMetadataResolver: OpenId4VCIService.makeMetadataResolver(networkingVci), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networkingVci), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networkingVci))).resolve(source: try .init(urlString: offerUri), policy: .ignoreSigned)
		switch result {
		case .success(let offer):
			let urlString = offer.credentialIssuerIdentifier.url.getBaseUrl()
			let credentialIssuerIdentifier = try CredentialIssuerId(urlString)
			let vciService = await OpenId4VCIServiceRegistry.shared.getByIssuerURL(issuerURL: credentialIssuerIdentifier.url.absoluteString)
			guard let vciService else {
				throw WalletError(description: "No OpenId4VCI service registered for name \(urlString)")
			}
			if let configuration {	await vciService.setConfiguration(configuration) }
			return try await vciService.issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes, txCodeValue: txCodeValue, promptMessage: promptMessage)
		case .failure(let error):
			throw PresentationSession.makeError(str: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	/// Begin issuing a document by generating an issue request
	///
	/// - Parameters:
	///   - id: Document identifier
	///   - credentialOptions: Credential options specifying batch size and credential policy
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - bDeferred: Whether this is for deferred issuance (default: false)
	/// - Returns: An issue request object that can be used to complete the issuance process
	public func beginIssueDocument(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, bDeferred: Bool = false) async throws -> IssueRequest {
		let request = try IssueRequest(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		return request
	}

	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?) async throws {
		try await storage.storageService.saveDocument(issued, batch: batch, allowOverwrite: true)
	}

	/// Load documents with a specific status from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	/// - Parameter status: Status of documents to load
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus) async throws -> [WalletStorage.Document]? {
		return try await storage.loadDocuments(status: status, uiCulture: uiCulture)
	}

	/// Load all documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	/// - Parameter status: Status of documents to load
	@discardableResult public func loadAllDocuments() async throws -> [WalletStorage.Document]? {
		var res: [WalletStorage.Document]?
		for status in WalletStorage.DocumentStatus.allCases {
			if let docs = (try await loadDocuments(status: status)) {
				res = (res ?? []) + docs
			}
		}
		return res
	}

	/// Load a document with a specific status from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: A `WalletStorage.Document` object
	/// - Parameter status: Status of document to load
	@discardableResult public func loadDocument(id: String, status: WalletStorage.DocumentStatus) async throws -> WalletStorage.Document? {
		return try await storage.loadDocument(id: id, uiCulture: uiCulture, status: status)
	}

	/// Delete documents with a specified status from storage
	///
	/// Calls ``storage`` deleteDocuments
	/// - Parameter status: Status of documents to delete
	public func deleteDocuments(status: WalletStorage.DocumentStatus) async throws  {
		return try await storage.deleteDocuments(status: status)
	}

	/// Delete all documents
	public func deleteAllDocuments() async throws {
		for status in WalletStorage.DocumentStatus.allCases {
			try await deleteDocuments(status: status)
		}
	}

	/// Delete document by id

	/// Deletes a document with the specified ID and status.
	/// - Parameters:
	///   - id: The unique identifier of the document to be deleted.
	///   - status: The current status of the document.
	///
	/// - Throws: An error if the document could not be deleted.
	public func deleteDocument(id: String, status: DocumentStatus) async throws {
		try await storage.deleteDocument(id: id, status: status)
	}

	/// Load sample data from json files
	///
	/// The mdoc data are stored in wallet storage as documents
	/// - Parameter sampleDataFiles: Names of sample files provided in the app bundle
	public func loadSampleData(sampleDataFiles: [String]? = nil) async throws {
		try? await storage.storageService.deleteDocuments(status: .issued)
		let docSamplesData = (sampleDataFiles ?? ["EUDI_sample_data"]).compactMap { Data(name:$0) }
			.compactMap(SignUpResponse.decomposeCBORSignupResponse(data:)).flatMap {$0}
		for dsd in docSamplesData {
			guard let pkCose = await CoseKeyPrivate.from(base64: dsd.pkData.base64EncodedString()) else { continue }
			let id = UUID().uuidString
			_ = try await pkCose.secureArea.createKeyBatch(id: id, credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1), keyOptions: nil)
			let displayName = dsd.docType == EuPidModel.euPidDocType ? "PID" : (dsd.docType == IsoMdlModel.isoDocType ? "mDL" : dsd.docType)
			let docMetadata = DocMetadata(credentialIssuerIdentifier: "", configurationIdentifier: "", docType: dsd.docType, display: [DisplayMetadata(name: displayName, localeIdentifier: "en_US")], issuerDisplay: [])
			let dki = DocKeyInfo(secureAreaName: SecureAreaRegistry.DeviceSecureArea.software.rawValue, batchSize: 1, credentialPolicy: .rotateUse)
			let docSample = Document(id: id, docType: dsd.docType, docDataFormat: .cbor, data: dsd.issData, docKeyInfo: dki.toData(), createdAt: Date.distantPast, metadata: docMetadata.toData(), displayName: displayName, status: .issued)
			try await storage.storageService.saveDocument(docSample, batch: nil, allowOverwrite: true)
		}
		do {
			try await storage.loadDocuments(status: .issued, uiCulture: uiCulture)
		} catch {
			await storage.setError(error)
			throw PresentationSession.makeError(str: error.localizedDescription)
		}
	}

	/// Get a document's remaining credentials, available for presentation count
	///
	/// - Parameters:
	///   - id: The unique identifier of the document to check usage counts for
	/// - Returns: A `CredentialsUsageCounts` object containing total and remaining presentation counts  if the document uses a one-time use policy, or `nil` if the document uses a rotate-use          policy (unlimited presentations)
	@available(*, deprecated, message: "Use credentialsUsageCount property of the DocClaimDecodable model instead")
	public func getCredentialsUsageCount(id: String) async throws -> CredentialsUsageCounts? {
		let uc = try await storage.getCredentialsUsageCount(id: id)
		storage.setUsageCount(uc, id: id)
		return uc
	}

	/// Prepare Service Data Parameters
	/// - Parameters:
	///   - docType: docType of documents to present (optional)
	/// - Returns: An ``InitializeTransferData`` instance that can be used to initialize a presentation service
	public func prepareServiceDataParameters(format: DocDataFormat? = nil) async throws -> (InitializeTransferData, [WalletStorage.Document]) {
		var parameters: InitializeTransferData
		guard var docs = try await storage.storageService.loadDocuments(status: .issued), docs.count > 0 else {
			throw PresentationSession.makeError(str: PresentationSession.NotAvailableStr, localizationKey: "request_data_no_document")
		}
		if let format { docs = docs.filter { $0.docDataFormat == format } }
		let idsToDocData = docs.compactMap { $0.getDataForTransfer() }
		var docKeyInfos = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.docKeyInfo))
		var docData = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.doc))
		var documentKeyIndexes = docData.mapValues { _ in 0 }
		for doc0 in docs {
			// find the credential to use based on usage counts and policy
			guard let dkid = docKeyInfos[doc0.id], let dki = DocKeyInfo(from: dkid) else { docKeyInfos[doc0.id] = nil; continue }
			let kbi = try await SecureAreaRegistry.shared.get(name: dki.secureAreaName).getKeyBatchInfo(id: doc0.id)
			guard kbi.batchSize > 1 else { if kbi.credentialPolicy == .oneTimeUse && kbi.usedCounts[0] > 0 { docKeyInfos[doc0.id] = nil }; continue }
			if let dclaims = storage.getDocumentModel(id: doc0.id), dclaims.validUntil == nil || dclaims.validUntil! < .now { docKeyInfos[doc0.id] = nil; continue }
			let doc = try await storage.storageService.loadDocument(id: doc0.id, status: .issued)
			docData[doc0.id] = doc?.data
			documentKeyIndexes[doc0.id] = doc?.keyIndex
		}
		docData = docData.filter { docKeyInfos[$0.key] != nil }
		guard idsToDocData.count > 0 else {
			throw PresentationSession.makeError(str:  PresentationSession.NotAvailableStr, localizationKey: "request_data_no_document")
		}
		let docMetadata = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.metadata))
		let idsToDocTypes = Dictionary(uniqueKeysWithValues: docs.filter({$0.docType != nil}).map { ($0.id, $0.docType!) })
		let docDisplayNames = Dictionary(uniqueKeysWithValues: docs.map { ($0.id, $0.getClaimDisplayNames(uiCulture)) })
		let jwtHashingAlgs = Dictionary(uniqueKeysWithValues: docs.map { ($0.id, StorageManager.getHashingAlgorithm(doc: $0))}).compactMapValues { $0 }
		parameters = InitializeTransferData(dataFormats: Dictionary(uniqueKeysWithValues: idsToDocData.map(\.fmt)), documentData: docData, documentKeyIndexes: documentKeyIndexes, docMetadata: docMetadata, docDisplayNames: docDisplayNames, docKeyInfos: docKeyInfos, trustedCertificates: trustedReaderCertificates ?? [], deviceAuthMethod: deviceAuthMethod.rawValue, idsToDocTypes: idsToDocTypes, hashingAlgs: jwtHashingAlgs)
		return (parameters, docs)
	}

	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - docType: DocType of documents to present (optional)
	/// - Returns: A presentation session instance,
	public func beginPresentation(flow: FlowType, sessionTransactionLogger: (any TransactionLogger)? = nil) async -> PresentationSession {
		do {
			let (parameters, documents) = try await prepareServiceDataParameters(format: flow == .ble ? .cbor : nil)
			let docIdToPresentInfo = try await storage.getDocIdsToPresentInfo(documents: documents)
			switch flow {
			case .ble:
				let bleSvc = try BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc, storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: userAuthenticationRequired, transactionLogger: sessionTransactionLogger ?? transactionLogger)
			case .openid4vp(let qrCode):
				let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode, openID4VpConfig: self.openID4VpConfig, networking: networkingVp)
				return PresentationSession(presentationService: openIdSvc, storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: userAuthenticationRequired, transactionLogger: sessionTransactionLogger ?? transactionLogger)
			default:
				return PresentationSession(presentationService: FaultPresentationService(error: PresentationSession.makeError(str: "Use beginPresentation(service:)")), storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: false, transactionLogger: sessionTransactionLogger ?? transactionLogger)
			}
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error), storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: [:], documentKeyIndexes: [:], userAuthenticationRequired: false, transactionLogger: sessionTransactionLogger ?? transactionLogger)
		}
	}

	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - service: An instance conforming to the ``PresentationService`` protocol that will
	///    be used to handle the presentation.
	///   - docType: DocType of documents to present (optional)
	/// - Returns: A `PresentationSession` instance,
	public func beginPresentation(service: any PresentationService, sessionTransactionLogger: TransactionLogger?) async -> PresentationSession {
		do {
			let (parameters, documents) = try await prepareServiceDataParameters()
			let docIdToPresentInfo = try await storage.getDocIdsToPresentInfo(documents: documents)
			return PresentationSession(presentationService: service, storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: docIdToPresentInfo,  documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: userAuthenticationRequired, transactionLogger: sessionTransactionLogger ?? self.transactionLogger)
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error), storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: [:], documentKeyIndexes: [:], userAuthenticationRequired: false, transactionLogger: sessionTransactionLogger ?? transactionLogger)
		}
	}

	/// Perform an action after user authorization via TouchID/FaceID/Passcode
	/// - Parameters:
	///   - dismiss: Action to perform if the user cancels authorization
	///   - action: Action to perform after user authorization
	public nonisolated static func authorizedAction<T: Sendable>(action: sending () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		return try await authorizedAction(isFallBack: false, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
	}

	/// Parse transaction log
	public func parseTransactionLog(_ transactionLog: TransactionLog) -> TransactionLogData {
		switch transactionLog.type {
			case .presentation: .presentation(log: PresentationLogData(transactionLog, uiCulture: uiCulture))
			case .issuance: .issuance
			case .signing: .signing
		}
	}

	/// Get document status
	public func getDocumentStatus(for statusIdentifier: StatusIdentifier) async throws -> CredentialStatus {
		let actor = DocumentStatusService(statusIdentifier: statusIdentifier)
		let status = try await actor.getStatus()
		return status
	}

	/// Executes an authorized action with optional fallback and dismissal handling.
	/// The action is performed after successful biometric authentication (TouchID or FaceID).
	///
	/// - Parameters:
	///   - isFallBack: A Boolean value indicating whether the action is a fallback after failed biometric authentication
	///  (ask for pin code). Default is `false`.
	///   - action: An asynchronous closure that performs the action and returns a result of type `T`.
	///   - disabled: A Boolean value indicating whether the action is disabled.
	///   - dismiss: A closure that handles the dismissal of the action.
	///   - localizedReason: A localized string providing the reason for the authorization request.
	///
	/// - Returns: An optional result of type `T` if the action is successful, otherwise `nil`.
	///
	/// - Throws: An error if the action fails.
	static nonisolated func authorizedAction<T: Sendable>(isFallBack: Bool = false, action: sending () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		guard !disabled else {
			return try await action()
		}
		let context = LAContext()
		var error: NSError?
		let policy: LAPolicy = .deviceOwnerAuthentication
		if context.canEvaluatePolicy(policy, error: &error) {
			do {
				let success = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
				#if os(iOS)
				if success, let scene = await UIApplication.shared.connectedScenes.first {
					let activateState = await scene.activationState
					if activateState != .foregroundActive {
					  // Delay the task by 1 second if not foreground
						try await Task.sleep(nanoseconds: 1_000_000_000)
					}
					return try await action()
				}
				else { dismiss(); }
				#else
				if success { return try await action() }
				#endif
			} catch let laError as LAError {
				if !isFallBack, laError.code == .userFallback {
					return try await authorizedAction(isFallBack: true, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
				} else {
					dismiss()
					return nil
				}
			}
		} else if let error {
			throw PresentationSession.makeError(str: error.localizedDescription)
		}
		return nil
	}
}
