/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import OpenID4VCI
import JOSESwift
import MdocDataModel18013
import AuthenticationServices
import Logging
import CryptoKit
import Security
import WalletStorage
import SwiftCBOR
import JOSESwift
import SwiftyJSON
import LocalAuthentication
import class eudi_lib_sdjwt_swift.CompactParser

public actor OpenId4VCIService {
	var issueReq: IssueRequest!
	let uiCulture: String?
	let logger: Logger
	var config: OpenId4VciConfiguration
	static nonisolated(unsafe) var credentialOfferCache = [String: CredentialOffer]()
	static nonisolated(unsafe) var issuerMetadataCache = [String: (CredentialIssuerId, CredentialIssuerMetadata)]()
	var networking: Networking
	var authRequested: AuthorizationRequested?
	var keyBatchSize: Int { issueReq.credentialOptions.batchSize }
	var storage: StorageManager
	var storageService: any DataStorageService
	@MainActor var simpleAuthWebContext: SimpleAuthenticationPresentationContext!
	typealias FuncKeyAttestationJWT = @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT

	init(uiCulture: String?, config: OpenId4VciConfiguration, networking: Networking, storage: StorageManager, storageService: any DataStorageService) throws {
		logger = Logger(label: "OpenId4VCI")
		guard config.credentialIssuerURL != nil else { throw PresentationSession.makeError(str: "credentialIssuerURL must be set in OpenId4VciConfiguration") }
		self.uiCulture = uiCulture
		self.networking = networking
		self.storage = storage
		self.storageService = storageService
		self.config = config
	}

	/// Prepare issuing by creating an issue request (id, private key) and an OpenId4VCI service instance
	/// - Parameters:
	///   - docType: document type
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: (Issue request key pair, vci service, unique id)
	func prepareIssuing(id: String, docTypeIdentifier: DocTypeIdentifier, displayName: String?, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, disablePrompt: Bool, promptMessage: String?) async throws {
		issueReq = try await EudiWallet.authorizedAction(action: {
			return try beginIssueDocument(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		}, disabled: !config.userAuthenticationRequired || disablePrompt, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(displayName ?? docTypeIdentifier.docTypeOrVct ?? docTypeIdentifier.value, comment: "")))
		guard issueReq != nil else {
			logger.error("User cancelled authentication")
			throw LAError(.userCancel)
		}
	}

	// create batch keys and return the binding keys and the `CoseKey` public keys in cbor format
	func initSecurityKeys(_ configuration: CredentialConfiguration) async throws -> ([BindingKey], [Data]) {
		let algSupported = Set(configuration.credentialSigningAlgValuesSupported)
		// Convert credential issuer supported algorithms to JWSAlgorithm types
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
		guard !algTypes.isEmpty else {
			throw PresentationSession.makeError(str: "No valid signing algorithms found in credential metadata: \(algSupported)")
		}
		// Find a compatible signing algorithm that both the secure area and credential issuer support
		let selectedAlgorithm = try findCompatibleSigningAlgorithm(algSupported: algTypes)
		guard let algType = Self.mapToJWSAlgorithmType(selectedAlgorithm) else {
			throw PresentationSession.makeError(str: "Unsupported secure area signing algorithm: \(selectedAlgorithm)")
		}
		let publicCoseKeys = try await issueReq.createKeyBatch()
		let publicKeys = try publicCoseKeys.map { try ECPublicKey(publicKey: try $0.toSecKey(), additionalParameters: ["alg": JWSAlgorithm(algType).name, "use": "sig", "kid": UUID().uuidString]) }
		let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
		var funcKeyAttestationJWT: FuncKeyAttestationJWT? = nil
		if config.keyAttestationsConfig != nil, configuration.supportsAttestationProofType {
			funcKeyAttestationJWT = { nonce in try await self.getKeyAttestationJWT(publicKeys, nonce: nonce) }
		} else if config.keyAttestationsConfig != nil, configuration.supportsJwtProofTypeWithAttestation {
			throw PresentationSession.makeError(str: "JWT proof with attestation is not yet supported in wallet")
		}
		let bindingKeys = try publicKeys.enumerated().map { try createBindingKey($0.element, secureAreaSigningAlg: selectedAlgorithm, unlockData: unlockData, index: $0.offset, funcKeyAttestationJWT: funcKeyAttestationJWT) }
		return (bindingKeys, publicCoseKeys.map { Data($0.toCBOR(options: CBOROptions()).encode()) })
	}

	func getKeyAttestationJWT(_ publicKeys: [ECPublicKey], nonce: String?) async throws -> KeyAttestationJWT {
		let jwt = try await self.config.keyAttestationsConfig!.walletAttestationsProvider.getKeysAttestation(keys: publicKeys, nonce: nonce!)
		let keyAttestationJwt: KeyAttestationJWT = try .init(jws: .init(compactSerialization: jwt))
		return keyAttestationJwt
	}

	func setConfiguration(_ config: OpenId4VciConfiguration) {
		self.config = config
	}

	func createBindingKey(_ publicKeyJWK: ECPublicKey, secureAreaSigningAlg: MdocDataModel18013.SigningAlgorithm, unlockData: Data?, index: Int, funcKeyAttestationJWT: FuncKeyAttestationJWT?) throws -> BindingKey {
		let algType = Self.mapToJWSAlgorithmType(secureAreaSigningAlg)!
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, index: index, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		let bindingKey: BindingKey
		if funcKeyAttestationJWT == nil {
			bindingKey = .jwt(algorithm: JWSAlgorithm(algType), jwk: publicKeyJWK, privateKey: .custom(signer), issuer: config.clientId)
		} else {
			bindingKey = try! .jwtKeyAttestation(algorithm: JWSAlgorithm(algType), keyAttestationJWT: funcKeyAttestationJWT!, keyIndex: UInt(index), privateKey: .custom(signer), issuer: config.clientId)
		}
		return bindingKey
	}

	func createKeyBatch() async throws {
		_ = try await issueReq.createKeyBatch()
	}

	static func clearCachedOfferMetadata(offerUri: String? = nil) {
		if let offerUri { Self.credentialOfferCache.removeValue(forKey: offerUri) }
		else { Self.credentialOfferCache.removeAll() }
	}

	/// Clear the issuer metadata cache
	static func clearIssuerMetadataCache() {
		Self.issuerMetadataCache.removeAll()
	}

	public nonisolated func beginIssueDocument(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, bDeferred: Bool = false) throws -> IssueRequest {
		let ir = try IssueRequest(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		return ir
	}

	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?) async throws {
		try await storageService.saveDocument(issued, batch: batch, allowOverwrite: true)
	}

	public func resolveOfferUrlDocTypes(offerUri: String) async throws -> OfferedIssuanceModel {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher<CredentialOfferRequestObject>(session: networking), credentialIssuerMetadataResolver: Self.makeMetadataResolver(networking), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking))).resolve(source: try .init(urlString: offerUri), policy: .ignoreSigned)
		switch result {
		case .success(let offer):
			return try await resolveOfferDocTypes(offerUri: offerUri, offer: offer)
		case .failure(let error):
			throw PresentationSession.makeError(str: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(offerUri: String, offer: CredentialOffer) async throws -> OfferedIssuanceModel {
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		Self.credentialOfferCache[offerUri] = offer
		let credentialInfo = try getCredentialOfferedModels(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance)
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: "")
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
	}

	func getDefaultCredentialOptions(batchCredentialIssuance: BatchCredentialIssuance?) -> CredentialOptions {
		let batchCredentialIssuanceSize = if let batchCredentialIssuance { batchCredentialIssuance.batchSize } else { 1 }
		return CredentialOptions(credentialPolicy: .rotateUse, batchSize: batchCredentialIssuanceSize)
	}

	func getMetadataDefaultCredentialOptions(_ docTypeIdentifier: DocTypeIdentifier) async throws -> CredentialOptions {
		let (_, metaData) = try await getIssuerMetadata()
		return CredentialOptions(credentialPolicy: .rotateUse, batchSize: metaData.batchCredentialIssuance?.batchSize ?? 1)
	}

	func getIssuer(offer: CredentialOffer) async throws -> Issuer {
		var dpopConstructor: DPoPConstructorType? = nil
		if config.useDpopIfSupported {
			dpopConstructor = try await config.makePoPConstructor(popUsage: .dpop, privateKeyId: issueReq.dpopKeyId, algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported, keyOptions: config.dpopKeyOptions)
		}
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported)
		return try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: vciConfig, parPoster: Poster(session: networking), tokenPoster: Poster(session: networking), requesterPoster: Poster(session: networking), deferredRequesterPoster: Poster(session: networking), notificationPoster: Poster(session: networking), noncePoster: Poster(session: networking), dpopConstructor: dpopConstructor)
	}

	public func getIssuerMetadata() async throws -> CredentialIssuerMetadata {
		let credentialIssuerIdentifier = try CredentialIssuerId(config.credentialIssuerURL!)
		let issuerMetadata = try await Self.makeMetadataResolver(networking).resolve(source: .credentialIssuer(credentialIssuerIdentifier), policy: .ignoreSigned)
		switch issuerMetadata {
			case .success(let metaData): return metaData
			case .failure(let error):
				throw PresentationSession.makeError(str: "Failed to retrieve issuer metadata: \(error.localizedDescription)")
		}
	}

	func getIssuerForDeferred(data: DeferredIssuanceModel) async throws -> Issuer {
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: data.configuration.credentialIssuerIdentifier, clientAttestationPopSigningAlgValuesSupported: data.configuration.clientAttestationPopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) }.compactMap { $0 })
		return try Issuer.createDeferredIssuer(deferredCredentialEndpoint: data.deferredCredentialEndpoint, deferredRequesterPoster: Poster(session: networking), config: vciConfig)
	}

	func authorizeOffer(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String?) async throws -> (AuthorizeRequestOutcome, Issuer, [CredentialConfiguration]) {
		guard let offer = Self.credentialOfferCache[offerUri] else {
			throw PresentationSession.makeError(str: "offerUri \(offerUri) not resolved. resolveOfferDocTypes must be called first")
		}
		let credentialInfos = docTypeModels.compactMap { try? getCredentialConfiguration(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, vct: $0.vct, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance, dpopSigningAlgValuesSupported: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)) }
		guard credentialInfos.count > 0, credentialInfos.count == docTypeModels.count else {
			throw PresentationSession.makeError(str: "Missing Credential identifiers - expected: \(docTypeModels.count), found: \(credentialInfos.count)")
		}
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try await getIssuer(offer: offer)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil {
			throw PresentationSession.makeError(str: "A transaction code is required for this offer")
		}
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported)
		let authorizedOutcome = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) { AuthorizeRequestOutcome.authorized(try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: vciConfig.client, transactionCode: txCodeValue).get()) } else { try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer) }
		return (authorizedOutcome, issuer, credentialInfos)
	}

	func issueDocumentByOfferUrl(issuer: Issuer, offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], promptMessage: String? = nil) async throws -> IssuanceOutcome {
		if case .presentation_request(let url) = authorizedOutcome, let authRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.credentialOfferCache[uuid] = offer
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else {
			throw PresentationSession.makeError(str: "Invalid authorized request outcome")
		}
		let id = configuration.configurationIdentifier.value; let sc = configuration.scope; let dn = configuration.display.getName(uiCulture) ?? ""
		logger.info("Starting issuing with identifer \(id), scope \(sc ?? ""), displayName: \(dn)")
		let res = try await Self.submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)
		// logger.info("Credential str:\n\(str)")
		return res
	}

	static func makeMetadataResolver(_ networking: any Networking) -> CredentialIssuerMetadataResolver {
	 CredentialIssuerMetadataResolver(fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: networking), processor: MetadataProcessor()))
	}

	func getIssuerMetadata() async throws -> (CredentialIssuerId, CredentialIssuerMetadata) {
		// Check cache first
		if let cachedResult = Self.issuerMetadataCache[config.credentialIssuerURL!] {
			return cachedResult
		}
		let credentialIssuerIdentifier = try CredentialIssuerId(config.credentialIssuerURL!)
		let issuerMetadata = try await Self.makeMetadataResolver(networking).resolve(source: .credentialIssuer(credentialIssuerIdentifier), policy: .ignoreSigned)
		switch issuerMetadata {
		case .success(let metaData):
			let result = (credentialIssuerIdentifier, metaData)
			Self.issuerMetadataCache[config.credentialIssuerURL!] = result
			return result
		case .failure(let error):
			throw PresentationSession.makeError(str: "Failed to resolve issuer metadata: \(error.localizedDescription)")
		}
	}

	func validateCredentialOptions(docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, offer: CredentialOffer? = nil) async throws -> CredentialOptions {
		let defaultCredentialOptions: CredentialOptions
		if let offer  {
			let batchCredentialIssuance = offer.credentialIssuerMetadata.batchCredentialIssuance
			defaultCredentialOptions = CredentialOptions(credentialPolicy: .rotateUse, batchSize: batchCredentialIssuance?.batchSize ?? 1)
		} else {
			// get the metadata from the offer based on the docTypeIdentifier
			defaultCredentialOptions = try await getMetadataDefaultCredentialOptions(docTypeIdentifier)
		}
		var usedCredentialOptions = credentialOptions ?? defaultCredentialOptions
		if let credentialOptions, defaultCredentialOptions.batchSize < credentialOptions.batchSize {
			logger.warning("Credential options batch size \(credentialOptions.batchSize) is larger than the default batch size \(defaultCredentialOptions.batchSize). Using the default batch size.")
			usedCredentialOptions.batchSize = defaultCredentialOptions.batchSize
		}
		return usedCredentialOptions
	}

	/// Issue multiple documents using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	/// - Parameters:
	///   - docTypeIdentifiers: Array of document type identifiers (msoMdoc, sdJwt, or configuration identifier)
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, defaults are fetched from issuer metadata.
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: Array of issued documents. They are saved in storage.
	@discardableResult public func issueDocuments(docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		if docTypeIdentifiers.isEmpty { return [] }
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		guard let authorizationServer = metaData.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		// Build credential configurations for each docTypeIdentifier
		var credentialConfigurations: [CredentialConfiguration] = []
		var configurationIdentifiers: [CredentialConfigurationIdentifier] = []
		for docTypeIdentifier in docTypeIdentifiers {
			let configuration = try getCredentialConfiguration(
				credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""),
				issuerDisplay: metaData.display,
				credentialsSupported: metaData.credentialsSupported,
				identifier: docTypeIdentifier.configurationIdentifier,
				docType: docTypeIdentifier.docType,
				vct: docTypeIdentifier.vct,
				batchCredentialIssuance: metaData.batchCredentialIssuance,
				dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name),
				clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)
			)
			credentialConfigurations.append(configuration)
			configurationIdentifiers.append(configuration.configurationIdentifier)
		}
		// Create a credential offer with all configurations
		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metaData,
			credentialConfigurationIdentifiers: configurationIdentifiers,
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)
		// Cache the offer with a generated UUID
		let offerUri = UUID().uuidString
		Self.credentialOfferCache[offerUri] = offer
		// Build OfferedDocModel array from configurations
		let docTypes: [OfferedDocModel] = credentialConfigurations.map { config in
			OfferedDocModel(
				credentialConfigurationIdentifier: config.configurationIdentifier.value,
				docType: config.docType,
				vct: config.vct,
				scope: config.scope ?? "",
				identifier: config.configurationIdentifier.value,
				displayName: config.display.getName(uiCulture) ?? config.docType ?? config.vct ?? config.scope ?? "",
				algValuesSupported: config.credentialSigningAlgValuesSupported,
				claims: config.claims,
				credentialOptions: credentialOptions ?? config.defaultCredentialOptions,
				keyOptions: keyOptions
			)
		}
		// Delegate to issueDocumentsByOfferUrl
		return try await issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes, txCodeValue: nil, promptMessage: promptMessage)
	}

	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: offered doc models available to be issued. Contains key options (secure are name and other options)
	///   - txCodeValue: Transaction code given to user (if available)
	///   - promptMessage: prompt message for biometric authentication (optional)
	/// - Returns: Array of issued and stored documents
	public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		if docTypes.isEmpty { return [] }
		guard let offer = Self.credentialOfferCache[offerUri] else {
			throw PresentationSession.makeError(str: "Offer URI not resolved: \(offerUri)")
		}
		
		var openId4VCIServices = [OpenId4VCIService]()
		for (i, docTypeModel) in docTypes.enumerated() {
			guard let docTypeIdentifier = docTypeModel.docTypeIdentifier else { continue }
			let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: docTypeModel.credentialOptions, offer: offer)
			let svc = try OpenId4VCIService(uiCulture: uiCulture,  config: config, networking: networking, storage: storage, storageService: storageService)
			try await svc.prepareIssuing(id: UUID().uuidString, docTypeIdentifier: docTypeIdentifier, displayName: i > 0 ? nil : docTypes.map(\.displayName).joined(separator: ", "), credentialOptions: usedCredentialOptions, keyOptions: docTypeModel.keyOptions, disablePrompt: i > 0, promptMessage: promptMessage)
			openId4VCIServices.append(svc)
		}
		let (auth, issuer, credentialInfos) = try await openId4VCIServices.first!.authorizeOffer(offerUri: offerUri, docTypeModels: docTypes, txCodeValue: txCodeValue)
		let documents = try await withThrowingTaskGroup(of: WalletStorage.Document.self) { group in
			for (i, openId4VCIService) in openId4VCIServices.enumerated() {
				group.addTask {
					let (bindingKeys, publicKeys) = try await openId4VCIService.initSecurityKeys(credentialInfos[i])
					let docData = try await openId4VCIService.issueDocumentByOfferUrl(issuer: issuer, offer: offer, authorizedOutcome: auth, configuration: credentialInfos[i], bindingKeys: bindingKeys, publicKeys: publicKeys, promptMessage: promptMessage)
					return try await self.finalizeIssuing(issueOutcome: docData, docType: docTypes[i].docTypeOrVct, format: credentialInfos[i].format, issueReq: openId4VCIService.issueReq)
				}
			}
			var result =  [WalletStorage.Document]()
			for try await doc in group { result.append(doc) }
			return result
		}
		return documents
	}	

	func getCredentialConfiguration(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, vct: String?, batchCredentialIssuance: BatchCredentialIssuance?, dpopSigningAlgValuesSupported: [String]?, clientAttestationPopSigningAlgValuesSupported: [String]?) throws -> CredentialConfiguration {
			if let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, docType != nil || identifier != nil, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope {
			logger.info("msoMdoc with scope \(scope), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			let jwtProofType = msoMdocConf.proofTypesSupported?["jwt"]
			let attestProofType = msoMdocConf.proofTypesSupported?["attestation"]
			let supportsJwtProofTypeWithoutAttestation = jwtProofType != nil && (jwtProofType?.keyAttestationRequirement == nil || jwtProofType?.keyAttestationRequirement == .notRequired)
			let supportsJwtProofTypeWithAttestation = jwtProofType != nil && !supportsJwtProofTypeWithoutAttestation

			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: msoMdocConf.docType, vct: nil, scope: scope, supportsAttestationProofType: attestProofType != nil, supportsJwtProofTypeWithAttestation: supportsJwtProofTypeWithAttestation, supportsJwtProofTypeWithoutAttestation: supportsJwtProofTypeWithoutAttestation, credentialSigningAlgValuesSupported: jwtProofType?.algorithms ?? [], dpopSigningAlgValuesSupported: dpopSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported: clientAttestationPopSigningAlgValuesSupported, issuerDisplay: issuerDisplay.map(\.displayMetadata), display: msoMdocConf.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: msoMdocConf.credentialMetadata?.claims ?? [], format: .cbor, defaultCredentialOptions: getDefaultCredentialOptions(batchCredentialIssuance: batchCredentialIssuance))
		} else if let credential =  credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtVc) = $0.value, vct != nil || identifier != nil, sdJwtVc.vct == vct || vct == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .sdJwtVc(sdJwtVc) = credential.value, let scope = sdJwtVc.scope {
			logger.info("sdJwtVc with scope \(scope), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
			let jwtProofType = sdJwtVc.proofTypesSupported?["jwt"]
			let attestProofType = sdJwtVc.proofTypesSupported?["attestation"]
			let supportsJwtProofTypeWithoutAttestation = jwtProofType != nil && (jwtProofType?.keyAttestationRequirement == nil || jwtProofType?.keyAttestationRequirement == .notRequired)
			let supportsJwtProofTypeWithAttestation = jwtProofType != nil && !supportsJwtProofTypeWithoutAttestation

			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: nil, vct: sdJwtVc.vct, scope: scope,  supportsAttestationProofType: attestProofType != nil, supportsJwtProofTypeWithAttestation: supportsJwtProofTypeWithAttestation,  supportsJwtProofTypeWithoutAttestation: supportsJwtProofTypeWithoutAttestation, credentialSigningAlgValuesSupported: jwtProofType?.algorithms ?? [], dpopSigningAlgValuesSupported: dpopSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported: clientAttestationPopSigningAlgValuesSupported, issuerDisplay: issuerDisplay.map(\.displayMetadata), display: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: sdJwtVc.credentialMetadata?.claims ?? [], format: .sdjwt, defaultCredentialOptions: getDefaultCredentialOptions(batchCredentialIssuance: batchCredentialIssuance))
		}
		let requestedParams = [docType.map { "docType: \($0)" }, vct.map { "vct: \($0)" }, identifier.map { "identifier: \($0)" }].compactMap { $0 }.joined(separator: ", ")
		logger.error("No credential configuration found with \(requestedParams). Available credential identifiers: \(credentialsSupported.keys.map(\.value).joined(separator: ", "))")
		throw WalletError(description: "Issuer does not support the requested credential with \(requestedParams).")
	}

	func getCredentialOfferedModels(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], batchCredentialIssuance: BatchCredentialIssuance?) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
			let credentialInfos = credentialsSupported.compactMap {
				if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let dco = getDefaultCredentialOptions(batchCredentialIssuance: batchCredentialIssuance), case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: msoMdocCred.docType, vct: nil, scope: scope, identifier: $0.key.value, displayName: msoMdocCred.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported, claims: msoMdocCred.credentialMetadata?.claims ?? [], credentialOptions: dco, keyOptions: nil) { (identifier: $0.key, scope: scope, offered: offered) }
				else if case .sdJwtVc(let sdJwtVc) = $0.value, let scope = sdJwtVc.scope, case let dco = getDefaultCredentialOptions(batchCredentialIssuance: batchCredentialIssuance), case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: nil, vct: sdJwtVc.vct, scope: scope, identifier: $0.key.value, displayName: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? scope, algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported, claims: sdJwtVc.credentialMetadata?.claims ?? [], credentialOptions: dco, keyOptions: nil) { (identifier: $0.key, scope: scope, offered: offered) }
				else { nil } }
			return credentialInfos
	}

	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizeRequestOutcome {
		let pushedAuthorizationRequestEndpoint = if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else { "" }
		if config.usePAR && pushedAuthorizationRequestEndpoint.isEmpty { logger.info("PAR not supported, Pushed Authorization Request Endpoint is nil") }
		logger.info("--> [AUTHORIZATION] Placing Request to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		let parPlaced = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)

		if case let .success(request) = parPlaced, case let .prepared(authRequested) = request {
			self.authRequested = authRequested
			logger.info("--> [AUTHORIZATION] Placed Request. Authorization code URL is: \(authRequested.authorizationCodeURL)")
			let authResult = try await loginUserAndGetAuthCode(authorizationCodeURL: authRequested.authorizationCodeURL.url)
			logger.info("--> [AUTHORIZATION] Authorization code retrieved")
			switch authResult {
			case .code(let authorizationCode):
				return .authorized(try await handleAuthorizationCode(issuer: issuer, offer: offer, request: request, authorizationCode: authorizationCode))
			case .presentation_request(let url):
				return .presentation_request(url)
			}
		} else if case let .failure(failure) = parPlaced {
			throw PresentationSession.makeError(str: "Authorization error: \(failure.localizedDescription)")
		}
		throw PresentationSession.makeError(str: "Failed to get push authorization code request")
	}

	private func handleAuthorizationCode(issuer: Issuer, offer: CredentialOffer, request: AuthorizationRequestPrepared, authorizationCode: String) async throws -> AuthorizedRequest {
		let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
		let unAuthorized = await issuer.handleAuthorizationCode(request: request, authorizationCode: issuanceAuthorization)
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(request: request, authorizationDetailsInTokenRequest: .doNotInclude, grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil)))
			if case let .success(authorized) = authorizedRequest {
				let at = authorized.accessToken
				logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
				_ = authorized.accessToken.isExpired(issued: authorized.timeStamp, at: Date().timeIntervalSinceReferenceDate)
				return authorized
			}
			throw PresentationSession.makeError(str: "Failed to get access token")
		case .failure(let error):
			throw PresentationSession.makeError(str: "Authorization code handling failed: \(error.localizedDescription)")
		}
	}

	private static func submissionUseCase(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], logger: Logger) async throws -> IssuanceOutcome {
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier)
		let requestOutcome = try await issuer.requestCredential(request: authorized, bindingKeys: bindingKeys, requestPayload: payload) { Issuer.createResponseEncryptionSpec($0) }
		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId, let interval):
						logger.info("Credential issuance deferred with transactionId: \(transactionId), interval: \(interval) seconds")
						// Prepare model for deferred issuance
						let derKeyData: Data? = if let encryptionSpec = await issuer.deferredResponseEncryptionSpec, let key = encryptionSpec.privateKey { try secCall { SecKeyCopyExternalRepresentation(key, $0)} as Data } else { nil }
						let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: authorized.accessToken, refreshToken: authorized.refreshToken, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, configuration: configuration, timeStamp: authorized.timeStamp)
						return .deferred(deferredModel)
					case .issued(let format, _, _, _):
						let credentials =  response.credentialResponses.compactMap { if case let .issued(_, cr, _, _) = $0 { cr } else { nil } }
						return try await Self.handleCredentialResponse(credentials: credentials, publicKeys: publicKeys, format: format, configuration: configuration, logger: logger)
					}
				} else {
					throw PresentationSession.makeError(str: "No credential response results available")
				}
			case .invalidProof(let errorDescription):
				throw PresentationSession.makeError(str: "Issuer error: " + (errorDescription ?? "The proof is invalid"))
			case .failed(let error):
				throw PresentationSession.makeError(str: error.localizedDescription)
			}
		case .failure(let error):
			throw PresentationSession.makeError(str: "Credential submission use case failed: \(error.localizedDescription)")
		}
	}

	private static func handleCredentialResponse(credentials: [Credential], publicKeys: [Data], format: String?, configuration: CredentialConfiguration, logger: Logger) async throws -> IssuanceOutcome {
		logger.info("Credential issued with format \(format ?? "unknown")")
		let toData: (String) -> Data = { str in
			if configuration.format == .cbor { return Data(base64URLEncoded: str) ?? Data() } else { return str.data(using: .utf8) ?? Data() }
		}
		let credData: [(Data, Data)] = try credentials.enumerated().flatMap { index, credential in
		if case let .string(str) = credential  {
			logger.notice("Issued credential data:\n\(str)")
			return [(toData(str), publicKeys[index])]
		} else if case let .json(json) = credential, json.type == .array, json.first != nil {
			let compactParser = CompactParser()
			let parseJsonToJwt = { (json: JSON) -> String in
				do { return try compactParser.stringFromJwsJsonObject(json) }
				catch { return json.stringValue }
			}
			let response = json.map { j in
				let str = parseJsonToJwt(j.1["credential"])
				return (toData(str), publicKeys[index])
			}
			logger.notice("Issued credential data:\n\(String(data: response.first!.0, encoding: .utf8) ?? "")")
			return response
		} else {
			throw PresentationSession.makeError(str: "Invalid credential")
		} }
		// keep dpop key may be reused
		// if config.dpopKeyOptions != nil { try? await issueReq.secureArea.deleteKeyBatch(id: issueReq.dpopKeyId, startIndex: 0, batchSize: 1); try? await issueReq.secureArea.deleteKeyInfo(id: issueReq.dpopKeyId) }
		return .issued(credData, configuration)
	}

		/// Request a deferred issuance based on a stored deferred document. On success, the deferred document is replaced with the issued document.
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - deferredDoc: A stored document with deferred status
	///   - credentialOptions: Credential options specifying batch size and credential policy for the deferred document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the deferred data are valid, otherwise a deferred status document
	@discardableResult public func requestDeferredIssuance(deferredDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		guard deferredDoc.status == .deferred else { throw PresentationSession.makeError(str: "Invalid document status for deferred issuance: \(deferredDoc.status)") }
		issueReq = try IssueRequest(id: deferredDoc.id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		let data = try await requestDeferredIssuance(deferredDoc: deferredDoc)
		guard case .issued(_, _) = data else { return deferredDoc }
		return try await finalizeIssuing(issueOutcome: data, docType: deferredDoc.docType, format: deferredDoc.docDataFormat, issueReq: issueReq)
	}

	func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try await getIssuerForDeferred(data: model)
		let authorized = AuthorizedRequest(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil, timeStamp: model.timeStamp, dPopNonce: nil, grant: nil)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId, publicKeys: model.publicKeys, derKeyData: model.derKeyData, configuration: model.configuration)
	}


	/// Resume pending issuance. Supports dynamic issuance scenario
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - pendingDoc: A temporary document with pending status
	///   - webUrl: The authorization URL returned from the presentation service (for dynamic issuance)
	///   - credentialOptions: Credential options specifying batch size and credential policy for the pending document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the pendingDoc data are valid, otherwise a pendingDoc status document
	@discardableResult public func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		guard pendingDoc.status == .pending, let docTypeIdentifier = pendingDoc.docTypeIdentifier else { throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")}
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(id: pendingDoc.id, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedCredentialOptions, keyOptions: keyOptions, disablePrompt: true, promptMessage: nil)
		let outcome = try await resumePendingIssuance(pendingDoc: pendingDoc, webUrl: webUrl)
		if case .pending(_) = outcome { return pendingDoc }
		let res = try await finalizeIssuing(issueOutcome: outcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: issueReq)
		return res
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else {
			throw PresentationSession.makeError(str: "Unknown pending reason: \(model.pendingReason)")
		}
		guard let webUrl else {
			throw PresentationSession.makeError(str: "Web URL not specified")
		}
		let asWeb = try await loginUserAndGetAuthCode(authorizationCodeURL: webUrl)
		guard case .code(let authorizationCode) = asWeb else {
			throw PresentationSession.makeError(str: "Pending issuance not authorized")
		}
		guard let offer = Self.credentialOfferCache[model.metadataKey] else {
			throw PresentationSession.makeError(str: "Pending issuance cannot be completed")
		}
		let issuer = try await getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.authorizeWithAuthorizationCode(request: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil)), grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))).get()
		let (bindingKeys, publicKeys) = try await initSecurityKeys(model.configuration)
		let res = try await Self.submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)
		return res
	}

	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId, publicKeys: [Data], derKeyData: Data?, configuration: CredentialConfiguration) async throws -> IssuanceOutcome {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		if let derKeyData {
			let deferredResponseEncryptionSpec = await Issuer.createResponseEncryptionSpec(issuer.issuerMetadata.credentialResponseEncryption, privateKeyData: derKeyData)
			await issuer.setDeferredResponseEncryptionSpec(deferredResponseEncryptionSpec)
		}
		let deferredRequestResponse = try await issuer.requestDeferredCredential(request: authorized, transactionId: transactionId, dPopNonce: nil)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(let credential):
				return try await Self.handleCredentialResponse(credentials: [credential], publicKeys: publicKeys, format: nil, configuration: configuration, logger: logger)
			case .issuancePending(let transactionId, let interval):
				logger.info("Credential not ready yet. Try after \(interval)")
				let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: authorized.accessToken, refreshToken: authorized.refreshToken, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, configuration: configuration, timeStamp: authorized.timeStamp)
				return .deferred(deferredModel)
			case .issuanceStillPending(let interval):
				logger.info("Credential still not ready. Try again after \(interval)")
				let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: authorized.accessToken, refreshToken: authorized.refreshToken, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, configuration: configuration, timeStamp: authorized.timeStamp)
				return .deferred(deferredModel)
			case .errored(_, let errorDescription):
				throw PresentationSession.makeError(str: "\(errorDescription ?? "Something went wrong with your deferred request response")")
			}
		case .failure(let error):
			throw PresentationSession.makeError(str: error.localizedDescription)
		}
	}

	@MainActor
	private func loginUserAndGetAuthCode(authorizationCodeURL: URL) async throws -> AsWebOutcome {
		#if os(iOS)
		if let scene = UIApplication.shared.connectedScenes.first {
			let activateState = scene.activationState
			if activateState != .foregroundActive { try await Task.sleep(nanoseconds: 1_000_000_000) }
		}
		#endif
		simpleAuthWebContext = SimpleAuthenticationPresentationContext()
		let lock = NSLock()
		return try await withCheckedThrowingContinuation { [redirectUrl = config.authFlowRedirectionURI.scheme!] continuation in
			var nillableContinuation: CheckedContinuation<AsWebOutcome, Error>? = continuation
			let authenticationSession = ASWebAuthenticationSession(url: authorizationCodeURL, callbackURLScheme: redirectUrl) { url, error in
				lock.lock()
				defer { lock.unlock() }
				if let error {
					nillableContinuation?.resume(throwing: OpenId4VCIError.authRequestFailed(error))
					nillableContinuation = nil
					return
				}
				guard let url else {
					nillableContinuation?.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl)
					nillableContinuation = nil
					return
				}
				if let schemes = Bundle.main.getURLSchemas(), schemes.first(where: { url.absoluteString.hasPrefix($0 + "://") }) != nil {
					// dynamic issuing case
					self.logger.info("Dynamic issuance url: \(url)")
					nillableContinuation?.resume(returning: .presentation_request(url))
					nillableContinuation = nil
				} else if let code = url.getQueryStringParameter("code") {
					self.logger.info("Authorization code: \(code)")
					nillableContinuation?.resume(returning: .code(code))
					nillableContinuation = nil
				} else {
					nillableContinuation?.resume(throwing: OpenId4VCIError.authorizeResponseNoCode)
					nillableContinuation = nil
				}
			}
			authenticationSession.presentationContextProvider = simpleAuthWebContext
			authenticationSession.start()
		}
	}

	final class SimpleAuthenticationPresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
		public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
			ASPresentationAnchor()
		}
	}

	/// Find a signing algorithm that is supported by both the secure area and the credential issuer
	private func findCompatibleSigningAlgorithm(algSupported: [JWSAlgorithm.AlgorithmType]) throws -> MdocDataModel18013.SigningAlgorithm {
		let secureAreasSupportedAlgorithms = Set(SecureAreaRegistry.shared.values.flatMap { type(of: $0).supportedEcCurves.map { $0.defaultSigningAlgorithm } }).sorted(by: {$0.order < $1.order})

		// Check if user has specified a preferred curve in keyOptions
		if let preferredCurve = issueReq.keyOptions?.curve {
			let preferredAlgorithm = preferredCurve.defaultSigningAlgorithm
			let preferredAlgType = Self.mapToJWSAlgorithmType(preferredAlgorithm)
			if let preferredAlgType, algSupported.contains(preferredAlgType) {
				return preferredAlgorithm
			}
		}
		// Otherwise, find the first compatible algorithm from the supported list
		for algorithm in secureAreasSupportedAlgorithms {
			if let algType = Self.mapToJWSAlgorithmType(algorithm), algSupported.contains(algType), let compatibleCurve = Self.getCompatibleCurve(for: algorithm) {
				// Update the issueReq.keyOptions to use the correct curve for this algorithm
				updateKeyOptionsForAlgorithm(algorithm: algorithm, curve: compatibleCurve)
				return algorithm
			}
		}
		throw PresentationSession.makeError(str: "Unable to find supported signing algorithm. Credential issuer supports: \(algSupported.map(\.rawValue)), secure area supports: \(secureAreasSupportedAlgorithms.map(\.rawValue))")
	}

	/// Get a compatible curve for the given signing algorithm
	static func getCompatibleCurve(for algorithm: MdocDataModel18013.SigningAlgorithm) -> CoseEcCurve? {
		switch algorithm {
		case .ES256: .P256; case .ES384: .P384; case .ES512: .P521; case .EDDSA: .ED25519
		case .UNSET: nil
		}
	}

	/// Update the issueReq.keyOptions to use the appropriate curve for the selected algorithm
	func updateKeyOptionsForAlgorithm(algorithm: MdocDataModel18013.SigningAlgorithm, curve: CoseEcCurve) {
		if issueReq.keyOptions == nil {
			issueReq.keyOptions = KeyOptions(curve: curve)
		} else if issueReq.keyOptions?.curve == nil || issueReq.keyOptions?.curve != curve {
			// Update the curve to match the selected algorithm
			issueReq.keyOptions?.curve = curve
		}
	}
	/// Map MdocDataModel18013.SigningAlgorithm to JWSAlgorithm.AlgorithmType, handling casing differences
	static func mapToJWSAlgorithmType(_ algorithm: MdocDataModel18013.SigningAlgorithm) -> JWSAlgorithm.AlgorithmType? {
		switch algorithm {
		case .ES256: .ES256; case .ES384: .ES384; case .ES512: .ES512; case .EDDSA: .EdDSA  // Handle the casing difference: EDDSA -> EdDSA
		default: nil
		}
	}

	func finalizeIssuing(issueOutcome: IssuanceOutcome, docType: String?, format: DocDataFormat, issueReq: IssueRequest) async throws -> WalletStorage.Document  {
		var dataToSave: Data; var docTypeToSave: String?
		var docMetadata: DocMetadata?; var displayName: String?
		let pds = issueOutcome.pendingOrDeferredStatus
		var batch: [WalletStorage.Document]?
		var publicKeys: [Data] = []
		var dkInfo = DocKeyInfo(secureAreaName: issueReq.secureAreaName, batchSize: 0, credentialPolicy: issueReq.credentialOptions.credentialPolicy)
		switch issueOutcome {
		case .issued(let dataPair, let cc):
			guard dataPair.first != nil else { throw PresentationSession.makeError(str: "Empty issued data array") }
			dataToSave = issueOutcome.getDataToSave(index: 0, format: format)
			docMetadata = cc.convertToDocMetadata()
			let docTypeOrVctOrScope = docType ?? cc.docType ?? cc.scope
			dkInfo.batchSize = dataPair.count
			docTypeToSave = if format == .cbor, dataToSave.count > 0 { (try IssuerSigned(data: [UInt8](dataToSave))).issuerAuth.mso.docType } else if format == .sdjwt, dataToSave.count > 0 { StorageManager.getVctFromSdJwt(docData: dataToSave) ?? docTypeOrVctOrScope } else { docTypeOrVctOrScope }
			displayName = cc.display.getName(uiCulture)
			if dataPair.count > 0 {
				batch = (0..<dataPair.count).map { WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: issueOutcome.getDataToSave(index: $0, format: format), docKeyInfo: nil, createdAt: Date(), metadata: nil, displayName: displayName, status: .issued) }
				publicKeys = dataPair.map(\.pk)
			}
		case .deferred(let deferredIssuanceModel):
			dataToSave = try JSONEncoder().encode(deferredIssuanceModel)
			docMetadata = deferredIssuanceModel.configuration.convertToDocMetadata()
			docTypeToSave = docType ?? "DEFERRED"
			displayName = deferredIssuanceModel.configuration.display.getName(uiCulture)
		case .pending(let pendingAuthModel):
			dataToSave = try JSONEncoder().encode(pendingAuthModel)
			docMetadata = pendingAuthModel.configuration.convertToDocMetadata()
			docTypeToSave = docType ?? "PENDING"
			displayName = pendingAuthModel.configuration.display.getName(uiCulture)
		}
		let newDocStatus: WalletStorage.DocumentStatus = issueOutcome.isDeferred ? .deferred : (issueOutcome.isPending ? .pending : .issued)
		let newDocument = WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: dataToSave, docKeyInfo: dkInfo.toData(), createdAt: Date(), metadata: docMetadata?.toData(), displayName: displayName, status: newDocStatus)
		if newDocStatus == .pending { await storage.appendDocModel(newDocument, uiCulture: uiCulture); return newDocument }
		if newDocStatus == .issued { try await validateIssuedDocuments(newDocument, batch: batch, publicKeys: publicKeys) }
		try await endIssueDocument(newDocument, batch: batch)
		await storage.appendDocModel(newDocument, uiCulture: uiCulture)
		await storage.refreshPublishedVars()
		if pds == nil { try await storage.removePendingOrDeferredDoc(id: issueReq.id) }
		return newDocument
	}

	func validateIssuedDocuments(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?, publicKeys: [Data]) async throws {
		let pkCoseKeys = publicKeys.compactMap { try? CoseKey(data: [UInt8]($0)) }
		guard pkCoseKeys.count == publicKeys.count else { throw PresentationSession.makeError(str: "Failed to parse public keys") }
		for (index, doc) in (batch ?? [issued]).enumerated() {
			do {
				if doc.docDataFormat == .cbor {
					let iss = try IssuerSigned(data: [UInt8](doc.data))
					guard let docType = doc.docType else { throw PresentationSession.makeError(str: "Document type missing at index \(index)") }
					try iss.validate(docType: docType)
				}
			}  catch let e as LocalizedError { throw PresentationSession.makeError(err: e) }
		}
	}

	func hasIssuerUrl(_ issuerURL: String) -> Bool {
		return config.credentialIssuerURL == issuerURL
	}

} // end of OpenId4VCIService

fileprivate extension URL {
	func getQueryStringParameter(_ parameter: String) -> String? {
		guard let url = URLComponents(string: self.absoluteString) else { return nil }
		return url.queryItems?.first(where: { $0.name == parameter })?.value
	}
}

public enum OpenId4VCIError: LocalizedError {
	case authRequestFailed(Error)
	case authorizeResponseNoUrl
	case authorizeResponseNoCode
	case tokenRequestFailed(Error)
	case tokenResponseNoData
	case tokenResponseInvalidData(String)
	case dataNotValid

	public var localizedDescription: String {
		switch self {
		case .authRequestFailed(let error):
			if let wae = error as? ASWebAuthenticationSessionError {
				if wae.code == .canceledLogin { return "The login has been canceled." }
				else if wae.code == .presentationContextNotProvided { return "Web authentication presenentation context not provided." }
				else if wae.code == .presentationContextInvalid { return "Web authentication presenentation context invalid." }
				else { return wae.localizedDescription}
			}
			return "Authorization request failed: \(error.localizedDescription)"
		case .authorizeResponseNoUrl:
			return "Authorization response does not include a url"
		case .authorizeResponseNoCode:
			return "Authorization response does not include a code"
		case .tokenRequestFailed(let error):
			return "Token request failed: \(error.localizedDescription)"
		case .tokenResponseNoData:
			return "No data received as part of token response"
		case .tokenResponseInvalidData(let reason):
			return "Invalid data received as part of token response: \(reason)"
		case .dataNotValid:
			return "Issued data not valid"
		}
	}
}

struct OpenID4VCINetworking: Networking {
	let networking: any NetworkingProtocol

	init(networking: any NetworkingProtocol) {
		self.networking = networking
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		try await networking.data(from: url)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		try await networking.data(for: request)
	}
}

extension Array where Element == OpenId4VCIService {
	public func getByIssuerURL(_ issuerURL: String) async -> OpenId4VCIService? {
		for service in self {
			if await service.hasIssuerUrl(issuerURL) {
				return service
			}
		}
		return nil
	}
}

/// Registry for OpenId4VCI services
public final class OpenId4VCIServiceRegistry: @unchecked Sendable {
	public static let shared = OpenId4VCIServiceRegistry()
	private var services: [String: OpenId4VCIService] = [:]
	private let lock = NSRecursiveLock()

	private init() {}

	public func register(name: String, service: OpenId4VCIService) {
		lock.lock()
		defer { lock.unlock() }
		services[name] = service
	}

	public func get(name: String) -> OpenId4VCIService? {
		lock.lock()
		defer { lock.unlock() }
		return services[name]
	}

	public func getAllServices() -> [OpenId4VCIService] {
		lock.lock()
		defer { lock.unlock() }
		return Array(services.values)
	}

	public func getByIssuerURL(issuerURL: String) async -> OpenId4VCIService? {
		return await getAllServices().getByIssuerURL(issuerURL)
	}
}
