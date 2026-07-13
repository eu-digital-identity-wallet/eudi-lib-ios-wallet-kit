/*
 * Copyright (c) 2026 European Commission
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
import MdocSecurity18013
import AuthenticationServices
import Logging
import CryptoKit
import Security
import WalletStorage
import SwiftCBOR
import JOSESwift
import SwiftyJSON
import LocalAuthentication
import X509
import class eudi_lib_sdjwt_swift.ClaimsVerifier
import class eudi_lib_sdjwt_swift.CompactParser
import class eudi_lib_sdjwt_swift.SDJWTVerifier
import class eudi_lib_sdjwt_swift.SdJwtVcIssuerMetaDataFetcher
import class eudi_lib_sdjwt_swift.SignatureVerifier
import protocol eudi_lib_sdjwt_swift.KeyExpressible
import struct eudi_lib_sdjwt_swift.SignedSDJWT

public actor OpenId4VciService {
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
	var transactionLogger: (any TransactionLogger)?
	/// Trust configuration used to validate issuer (document-signer) certificate chains of issued documents.
	var trustConfig: TrustConfiguration
	@MainActor var simpleAuthWebContext: SimpleAuthenticationPresentationContext!
	typealias FuncKeyAttestationJWT = @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT

	init(uiCulture: String?, config: OpenId4VciConfiguration, networking: Networking, storage: StorageManager, storageService: any DataStorageService, trustConfig: TrustConfiguration, transactionLogger: (any TransactionLogger)? = nil) throws {
		logger = Logger(label: "OpenId4VCI")
		guard config.credentialIssuerURL != nil else { throw WalletError(description: "credentialIssuerURL must be set in OpenId4VciConfiguration", code: .internalError) }
		self.uiCulture = uiCulture
		self.networking = networking
		self.storage = storage
		self.storageService = storageService
		self.config = config
		self.trustConfig = trustConfig
		self.transactionLogger = transactionLogger
	}

	/// Prepare issuing by creating an issue request (id, private key) and an OpenId4VCI service instance
	/// - Parameters:
	///   - docType: document type
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: (Issue request key pair, vci service, unique id)
	func prepareIssuing(id: String, docTypeIdentifier: DocTypeIdentifier, displayName: String?, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, disablePrompt: Bool, promptMessage: String?, offer: CredentialOffer? = nil) async throws {
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions, offer: offer)
		let resolvedDocTypeName = displayName ?? docTypeIdentifier.docTypeOrVct ?? docTypeIdentifier.value
		let localizedDocTypeName = NSLocalizedString(resolvedDocTypeName, comment: "")
		let defaultLocalizedReason = NSLocalizedString("issue_document", comment: "")
		let localizedReason = promptMessage ?? defaultLocalizedReason.replacingOccurrences(of: "{docType}", with: localizedDocTypeName)
		issueReq = try await EudiWallet.authorizedAction(action: {
			return try beginIssueDocument(id: id, credentialOptions: usedCredentialOptions, keyOptions: keyOptions)
		}, disabled: !config.userAuthenticationRequired || disablePrompt, dismiss: {}, localizedReason: localizedReason)
		guard issueReq != nil else {
			logger.error("User cancelled authentication")
			throw LAError(.userCancel)
		}
	}

	// create batch keys and return the binding keys and the `CoseKey` public keys in cbor format
	func initSecurityKeys(_ configuration: CredentialConfiguration, issuer: String) async throws -> ([BindingKey], [Data]) {
		let algSupported = Set(configuration.credentialSigningAlgValuesSupported)
		// Convert credential issuer supported algorithms to JWSAlgorithm types
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
		guard !algTypes.isEmpty else {
			throw WalletError(description: "No valid signing algorithms found in credential metadata: \(algSupported)", code: .unsupportedAlgorithm)
		}
		// Find a compatible signing algorithm that both the secure area and credential issuer support
		let selectedAlgorithm = try findCompatibleSigningAlgorithm(algSupported: algTypes)
		guard let algType = Self.mapToJWSAlgorithmType(selectedAlgorithm) else {
			throw WalletError(description: "Unsupported secure area signing algorithm: \(selectedAlgorithm)", code: .unsupportedAlgorithm)
		}
		let publicCoseKeys = try await issueReq.createKeyBatch()
		let publicKeys = try Self.makePublicJwks(from: publicCoseKeys, algorithm: algType)
		let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
		let funcKeyAttestationJWT: FuncKeyAttestationJWT = { nonce in try await self.getKeyAttestationJWT(publicKeys, nonce: nonce) }
		let bindingKey: BindingKey
		if configuration.supportsAttestationProofType {
			// Send a single `attestation` proof for the whole batch. The key attestation JWT already attests every key
			bindingKey = .attestation(keyAttestationJWT: funcKeyAttestationJWT)
		} else if configuration.supportsJwtProofTypeWithAttestation {
			bindingKey = try createBindingKey(publicKeys.first!, secureAreaSigningAlg: selectedAlgorithm, unlockData: unlockData, index: 0, funcKeyAttestationJWT: funcKeyAttestationJWT, issuer: issuer)
		} else {
			throw WalletError(description: "Unsupported credential configuration", code: .unsupportedCredentialConfiguration)
		}
		return ([bindingKey], publicCoseKeys.map { Data($0.toCBOR(options: CBOROptions()).encode()) })
	}

	func createKeyBatchWithAttestation(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, nonce: String?) async throws -> BatchCreateKeyResult {
		let attestationProvider = config.keyAttestationsConfig.walletAttestationsProvider
		let request = try IssueRequest(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		let publicCoseKeys = try await request.createKeyBatch()
		let publicKeys = try Self.makePublicJwks(from: publicCoseKeys)
		let keyAttestation = try await attestationProvider.getKeysAttestation(keys: publicKeys, nonce: nonce)
		return BatchCreateKeyResult(keys: publicCoseKeys, keyAttestation: keyAttestation)
	}

	private static func makePublicJwks(from publicCoseKeys: [CoseKey], algorithm: JWSAlgorithm.AlgorithmType? = nil) throws -> [ECPublicKey] {
		try publicCoseKeys.map {
			var additionalParameters: [String: String] = ["use": "sig", "kid": UUID().uuidString]
			if let algorithm {
				additionalParameters["alg"] = JWSAlgorithm(algorithm).name
			}
			return try ECPublicKey(publicKey: try $0.toSecKey(), additionalParameters: additionalParameters)
		}
	}

	func getKeyAttestationJWT(_ publicKeys: [ECPublicKey], nonce: String?) async throws -> KeyAttestationJWT {
		let jwt = try await self.config.keyAttestationsConfig.walletAttestationsProvider.getKeysAttestation(keys: publicKeys, nonce: nonce!)
		let keyAttestationJwt: KeyAttestationJWT = try .init(jws: .init(compactSerialization: jwt))
		return keyAttestationJwt
	}

	func setConfiguration(_ config: OpenId4VciConfiguration) {
		self.config = config
	}

	func createBindingKey(_ publicKeyJWK: ECPublicKey, secureAreaSigningAlg: MdocDataModel18013.SigningAlgorithm, unlockData: Data?, index: Int, funcKeyAttestationJWT: @escaping FuncKeyAttestationJWT, issuer: String) throws -> BindingKey {
		let algType = Self.mapToJWSAlgorithmType(secureAreaSigningAlg)!
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, index: index, publicKey: publicKeyJWK, curve: publicKeyJWK.crv.coseEcCurve, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		let bindingKey: BindingKey
		bindingKey = try .jwtKeyAttestation(algorithm: JWSAlgorithm(algType), keyAttestationJWT: funcKeyAttestationJWT, keyIndex: UInt(index), privateKey: .custom(signer), issuer: issuer)
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
		let fetcher = Fetcher<CredentialOfferRequestObject>(session: networking)
		let metadataResolver = Self.makeMetadataResolver(networking)
		let oidcFetcher = Fetcher<OIDCProviderMetadata>(session: networking)
		let oauthFetcher = Fetcher<AuthorizationServerMetadata>(session: networking)
		let authorizationResolver = AuthorizationServerMetadataResolver(oidcFetcher: oidcFetcher, oauthFetcher: oauthFetcher)
		let resolver = CredentialOfferRequestResolver(fetcher: fetcher, credentialIssuerMetadataResolver: metadataResolver, authorizationServerMetadataResolver: authorizationResolver)
		let result = await resolver.resolve(source: try .init(urlString: offerUri), policy: config.issuerMetadataPolicy)
		switch result {
		case .success(let offer):
			return try await resolveOfferDocTypes(offerUri: offerUri, offer: offer)
		case .failure(let error):
			throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)", code: .offerResolutionFailed, innerError: error)
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
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
	}

	func resolveCredentialOptions(batchCredentialIssuance: BatchCredentialIssuance?, credentialReusePolicy: CredentialReusePolicy? = nil, userCredentialOptions: CredentialOptions? = nil) throws -> CredentialOptions {
		let selectedPolicy = try CredentialReusePolicyValidator.selectMatchingPolicy(
			issuerPolicy: credentialReusePolicy,
			walletSupported: OpenId4VciConfiguration.supportedCredentialReusePolicies
		)
		var issuerSpecifiedBatchSize = CredentialReusePolicyValidator.determineBatchSize(
			selectedPolicy: selectedPolicy,
			issuerBatchSize: batchCredentialIssuance?.batchSize
		) ?? 1
		// Limited-time dictates that a single instance of the attestation is issued that can be used for a limited period.
		if let selectedPolicy, selectedPolicy.method == .limitedTime { issuerSpecifiedBatchSize = 1 }
		let reissueTriggerUnused: Int?
		let reissueTriggerLifetimeLeft: Int?
		switch selectedPolicy {
		case .onceOnly(_, let triggerUnused):
			reissueTriggerUnused = triggerUnused
			reissueTriggerLifetimeLeft = nil
		case .limitedTime(let triggerLifetimeLeft):
			reissueTriggerUnused = nil
			reissueTriggerLifetimeLeft = triggerLifetimeLeft
		case .rotatingBatch(_, let triggerLifetimeLeft):
			reissueTriggerUnused = nil
			reissueTriggerLifetimeLeft = triggerLifetimeLeft
		case .perRelyingParty(_, let triggerUnused, let triggerLifetimeLeft):
			reissueTriggerUnused = triggerUnused
			reissueTriggerLifetimeLeft = triggerLifetimeLeft
		case nil:
			reissueTriggerUnused = nil
			reissueTriggerLifetimeLeft = nil
		}
		let resolvedPolicy: CredentialPolicy = if case .onceOnly = selectedPolicy { .oneTimeUse } else { .rotateUse }
		var resolved = userCredentialOptions ?? CredentialOptions(
			credentialPolicy: resolvedPolicy,
			batchSize: issuerSpecifiedBatchSize,
			reissueTriggerUnused: reissueTriggerUnused,
			reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft
		)
		if resolved.batchSize > issuerSpecifiedBatchSize {
			logger.warning("Credential options batch size \(resolved.batchSize) is larger than the default batch size \(issuerSpecifiedBatchSize). Using the default batch size.")
			resolved.batchSize = issuerSpecifiedBatchSize
		}
		if credentialReusePolicy != nil {
			// Issuer-defined reuse policy takes precedence over user-provided policy fields.
			resolved.credentialPolicy = resolvedPolicy
			resolved.batchSize = issuerSpecifiedBatchSize
			resolved.reissueTriggerUnused = reissueTriggerUnused
			resolved.reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft
		}
		return resolved
	}

	func getIssuerReusePolicy(_ docTypeIdentifier: DocTypeIdentifier, credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported]) -> CredentialReusePolicy? {
		let matchingCredential = credentialsSupported.first {
			switch $0.value {
			case .msoMdoc(let msoMdoc):
				return if let identifier = docTypeIdentifier.configurationIdentifier { $0.key.value == identifier }
				else if let docType = docTypeIdentifier.docType { msoMdoc.docType == docType }
				else { false }
			case .sdJwtVc(let sdJwtVc):
				return if let identifier = docTypeIdentifier.configurationIdentifier { $0.key.value == identifier }
				else if let vct = docTypeIdentifier.vct { sdJwtVc.vct == vct }
				else { false }
			default:
				return false
			}
		}?.value
		return switch matchingCredential {
		case .msoMdoc(let msoMdoc): msoMdoc.credentialMetadata?.credentialReusePolicy
		case .sdJwtVc(let sdJwtVc): sdJwtVc.credentialMetadata?.credentialReusePolicy
		default: nil
		}
	}

	func getMetadataDefaultCredentialOptions(_ docTypeIdentifier: DocTypeIdentifier, offerMetadata: CredentialIssuerMetadata? = nil, userCredentialOptions: CredentialOptions? = nil) async throws -> CredentialOptions {
		let metaData: CredentialIssuerMetadata = if let offerMetadata { offerMetadata } else { try await getIssuerMetadata() }
		let issuerReusePolicy = getIssuerReusePolicy(docTypeIdentifier, credentialsSupported: metaData.credentialsSupported)
		return try resolveCredentialOptions(batchCredentialIssuance: metaData.batchCredentialIssuance, credentialReusePolicy: issuerReusePolicy, userCredentialOptions: userCredentialOptions)
	}

	func getIssuer(offer: CredentialOffer, dpopKeyId: String? = nil) async throws -> Issuer {
		var dpopConstructor: DPoPConstructorType? = nil
		if config.requireDpop {
			dpopConstructor = try await config.makePoPConstructor(popUsage: .dpop, privateKeyId: dpopKeyId ?? issueReq.dpopKeyId, algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported, keyOptions: config.dpopKeyOptions)
		}
		guard let algs = offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported else { throw WalletError(description: "No client attestation POP signing algorithms found", code: .noClientAttestationAlgorithmFound) }
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: algs)
		return try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: vciConfig, parPoster: Poster(session: networking), tokenPoster: Poster(session: networking), requesterPoster: Poster(session: networking), deferredRequesterPoster: Poster(session: networking), notificationPoster: Poster(session: networking), noncePoster: Poster(session: networking), dpopConstructor: dpopConstructor)
	}

	public func getIssuerMetadata() async throws -> CredentialIssuerMetadata {
		let (_, metadata) = try await resolveIssuerMetadata()
		return metadata
	}

	func getIssuerForDeferred(data: DeferredIssuanceModel, configuration: CredentialConfiguration, dpopKeyId: String? = nil) async throws -> (Issuer,DPoPConstructor?) {
		guard let algs = configuration.clientAttestationPopSigningAlgValuesSupported else { throw WalletError(description: "No client attestation POP signing algorithms found", code: .noClientAttestationAlgorithmFound) }
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: configuration.credentialIssuerIdentifier, clientAttestationPopSigningAlgValuesSupported: algs.map { JWSAlgorithm(name: $0) })
		var dpopConstructor: DPoPConstructor? = nil
		let dpopSigningAlgValuesSupported = configuration.dpopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) }
		if config.requireDpop {
			dpopConstructor = try await config.makePoPConstructor(popUsage: .dpop, privateKeyId: dpopKeyId ?? issueReq.dpopKeyId, algorithms: dpopSigningAlgValuesSupported, keyOptions: config.dpopKeyOptions)
		}
		let (_, issuerMetadata) = try await resolveIssuerMetadata()
		guard let authorizationServer = issuerMetadata.authorizationServers?.first else {
			throw WalletError(description: "Invalid authorization server - no authorization server found", code: .authorizationFailed)
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		let issuer = try Issuer(authorizationServerMetadata: authorizationServerMetadata, issuerMetadata: .init(deferredCredentialEndpoint: data.deferredCredentialEndpoint), config: vciConfig, dpopConstructor: dpopConstructor, session: networking)
		return (issuer, dpopConstructor)
	}

	func authorizeOffer(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String?, authorized: AuthorizedRequest?, forceRefreshToken: Bool, backgroundOnly: Bool = false, dpopKeyId: String? = nil) async throws -> (AuthorizeRequestOutcome, Issuer, [CredentialConfiguration]) {
		guard let offer = Self.credentialOfferCache[offerUri] else {
			throw WalletError(description: "offerUri \(offerUri) not resolved. resolveOfferDocTypes must be called first", code: .internalError)
		}
		let credentialConfigurations = docTypeModels.compactMap { try? getCredentialConfiguration(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString, issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, vct: $0.vct, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance, dpopSigningAlgValuesSupported: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)) }
		guard credentialConfigurations.count > 0, credentialConfigurations.count == docTypeModels.count else {
			throw WalletError(description: "Missing Credential identifiers - expected: \(docTypeModels.count), found: \(credentialConfigurations.count)", code: .internalError)
		}
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try await getIssuer(offer: offer, dpopKeyId: dpopKeyId)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil {
			throw WalletError(description: "A transaction code is required for this offer", code: .authorizationFailed)
		}
		let authorizedOutcome: AuthorizeRequestOutcome
		if var authorized {
			do {
				logger.info("Access token issued at: \(Date(timeIntervalSinceReferenceDate:authorized.timeStamp)), now: \(Date()), expires at \(Date(timeIntervalSinceReferenceDate:authorized.timeStamp + (authorized.accessToken.expiresIn ?? 0)))")
				authorized = try await refreshAuthorization(issuer: issuer, authorized: authorized,	configuration: credentialConfigurations[0], forceRefreshToken: forceRefreshToken)
				authorizedOutcome = .authorized(authorized)
				return (authorizedOutcome, issuer, credentialConfigurations)
			}
			catch CredentialIssuanceError.requestFailed(let code, let error, let description) where !backgroundOnly && forceRefreshToken && (400..<500).contains(code) {
				logger.error("Refresh token authentication failure with status code: \(code), error: \(error) \(description ?? "").")
			}
		}
		if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) {
			guard let algs = offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported else { throw WalletError(description: "No client attestation POP signing algorithms found", code: .noClientAttestationAlgorithmFound) }
			let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: algs)
			let authorized = try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: vciConfig.client, transactionCode: txCodeValue)
			authorizedOutcome = .authorized(authorized)
		} else if !backgroundOnly {
			authorizedOutcome = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
		} else {
			throw WalletError(description: "Offer requires user interaction for authorization, but backgroundOnly is set to true, forced refresh token is \(forceRefreshToken).", code: .authorizationFailed)
		}
		return (authorizedOutcome, issuer, credentialConfigurations)
	}

	func issueDocumentByOfferUrl(issuer: Issuer, offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], promptMessage: String? = nil) async throws -> IssuanceOutcome {
		if case .presentation_request(let url) = authorizedOutcome, let authRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.credentialOfferCache[uuid] = offer
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod, state: authRequested.state ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else {
			throw WalletError(description: "Invalid authorized request outcome", code: .authorizationFailed)
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

	func resolveIssuerMetadata() async throws -> (CredentialIssuerId, CredentialIssuerMetadata) {
		// Check cache first
		if let cachedResult = Self.issuerMetadataCache[config.credentialIssuerURL!] {
			return cachedResult
		}
		let credentialIssuerIdentifier = try CredentialIssuerId(config.credentialIssuerURL!)
		let issuerMetadata = try await Self.makeMetadataResolver(networking).resolve(source: .credentialIssuer(credentialIssuerIdentifier), policy: config.issuerMetadataPolicy)
		switch issuerMetadata {
		case .success(let metaData):
			let result = (credentialIssuerIdentifier, metaData)
			Self.issuerMetadataCache[config.credentialIssuerURL!] = result
			return result
		case .failure(let error):
			let errorDescription = error.localizedDescription
			throw WalletError(description: "Failed to resolve issuer metadata: \(errorDescription)", code: .issuerMetadataResolutionFailed, innerError: error)
		}
	}

	func validateCredentialOptions(docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, offer: CredentialOffer? = nil) async throws -> CredentialOptions {
		return try await getMetadataDefaultCredentialOptions(docTypeIdentifier, offerMetadata: offer?.credentialIssuerMetadata, userCredentialOptions: credentialOptions)
	}

	/// Reissue a document by loading its metadata from storage and resolving the credential configuration from the issuer
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	/// - Parameters:
	///   - documentId: The ID of the document to reissue
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, defaults from the configuration are used.
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: Array of issued documents. They are saved in storage.
	@discardableResult func reissueDocument(documentId: WalletStorage.Document.ID, docMetadata: DocMetadata, authorized: AuthorizedRequest? = nil, credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, backgroundOnly: Bool = false) async throws -> [WalletStorage.Document] {
		let (credentialConfigurations, offer) = try await buildCredentialOffer(for: [.identifier(docMetadata.configurationIdentifier)])
		let credentialConfiguration = credentialConfigurations.first!
		let offerUri = UUID().uuidString
		Self.credentialOfferCache[offerUri] = offer
		let docTypes = [makeOfferedDocModel(from: credentialConfiguration, credentialOptions: credentialOptions, keyOptions: keyOptions)]
		let reissueAction: (Bool) async throws -> [WalletStorage.Document] = { forceRefreshToken in
			return try await self.issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes, authorized: authorized, forceRefreshToken: forceRefreshToken, documentId: documentId, txCodeValue: nil, promptMessage: promptMessage, backgroundOnly: backgroundOnly, dpopKeyId: docMetadata.dpopKeyId)
		}
		do {
			return try await reissueAction(false)
		} catch CredentialIssuanceError.requestFailed(let code, let error, let description) where (400..<500).contains(code) {
				logger.error("Authentication failure with status code: \(code), error: \(error) \(description ?? "").")
			return try await reissueAction(true)
		}
		catch PostError.requestError(let code, let error) where (400..<500).contains(code) {
				logger.error("Authentication failure with status code: \(code), error: \(error).")
			return try await reissueAction(true)
		}
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
		let (credentialConfigurations, offer) = try await buildCredentialOffer(for: docTypeIdentifiers)
		// Cache the offer with a generated UUID
		let offerUri = UUID().uuidString
		Self.credentialOfferCache[offerUri] = offer
		// Build OfferedDocModel array from configurations
		let docTypes: [OfferedDocModel] = credentialConfigurations.map {
			makeOfferedDocModel(from: $0, credentialOptions: credentialOptions, keyOptions: keyOptions)
		}
		// Delegate to issueDocumentsByOfferUrl
		return try await issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes, authorized: nil, documentId: nil,  txCodeValue: nil, promptMessage: promptMessage)
	}

	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: offered doc models available to be issued. Contains key options (secure are name and other options)
	///   - txCodeValue: Transaction code given to user (if available)
	///   - promptMessage: prompt message for biometric authentication (optional)
	/// - Returns: Array of issued and stored documents
	func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], authorized: AuthorizedRequest?, forceRefreshToken: Bool = false, documentId: String?, txCodeValue: String? = nil, promptMessage: String? = nil, backgroundOnly: Bool = false, dpopKeyId: String? = nil) async throws -> [WalletStorage.Document] {
		if docTypes.isEmpty { return [] }
		guard let offer = Self.credentialOfferCache[offerUri] else {
			throw WalletError(description: "Offer URI not resolved: \(offerUri)", code: .offerResolutionFailed)
		}
		var openId4VCIServices = [OpenId4VciService]()
		for (i, docTypeModel) in docTypes.enumerated() {
			guard let docTypeIdentifier = docTypeModel.docTypeIdentifier else { continue }
			let svc = try OpenId4VciService(uiCulture: uiCulture,  config: config, networking: networking, storage: storage, storageService: storageService, trustConfig: trustConfig)
			if let documentId { logger.info("Resolve offer to update document with id \(documentId)") }
			let id = UUID().uuidString //(i == 0 ? documentId : nil) ?? UUID().uuidString
			try await svc.prepareIssuing(id: id, docTypeIdentifier: docTypeIdentifier, displayName: i > 0 ? nil : docTypes.map(\.displayName).joined(separator: ", "), credentialOptions: docTypeModel.credentialOptions, keyOptions: docTypeModel.keyOptions, disablePrompt: i > 0, promptMessage: promptMessage, offer: offer)
			openId4VCIServices.append(svc)
		}
		let (auth, issuer, credentialInfos) = try await openId4VCIServices.first!.authorizeOffer(offerUri: offerUri, docTypeModels: docTypes, txCodeValue: txCodeValue, authorized: authorized, forceRefreshToken: forceRefreshToken, backgroundOnly: backgroundOnly, dpopKeyId: dpopKeyId)
		let issuerIdentifier = offer.credentialIssuerIdentifier.url.absoluteString
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? issuerIdentifier
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		let documents = try await withThrowingTaskGroup(of: WalletStorage.Document.self) { group in
			for (i, openId4VCIService) in openId4VCIServices.enumerated() {
				group.addTask {
					let (bindingKeys, publicKeys) = try await openId4VCIService.initSecurityKeys(credentialInfos[i], issuer: issuerIdentifier)
					let docData = try await openId4VCIService.issueDocumentByOfferUrl(issuer: issuer, offer: offer, authorizedOutcome: auth, configuration: credentialInfos[i], bindingKeys: bindingKeys, publicKeys: publicKeys, promptMessage: promptMessage)
					return try await self.finalizeIssuing(issueOutcome: docData, docType: docTypes[i].docTypeOrVct, format: credentialInfos[i].format, issueReq: openId4VCIService.issueReq, deleteId: documentId, issuer: issuer, dpopKeyId: dpopKeyId, issuerName: issuerName, issuerIdentifier: issuerIdentifier, issuerLogoUrl: issuerLogoUrl)
				}
			}
			var result =  [WalletStorage.Document]()
			for try await doc in group { result.append(doc) }
			return result
		}
		return documents
	}

	func getCredentialConfiguration(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, vct: String?, batchCredentialIssuance: BatchCredentialIssuance?, dpopSigningAlgValuesSupported: [String]?, clientAttestationPopSigningAlgValuesSupported: [String]?) throws -> CredentialConfiguration {
		if case let credentials = credentialsSupported.filter({ if case .msoMdoc(let msoMdocCred) = $0.value, docType != nil || identifier != nil, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), let credential = credentials.first(where: { !$0.key.value.hasSuffix("_deferred")}) ?? credentials.first, case let .msoMdoc(msoMdocConf) = credential.value {
			logger.info("msoMdoc with scope \(String(describing: msoMdocConf.scope)), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			let proofTypesSupported = msoMdocConf.proofTypesSupported ?? [:]
			let (jwtProofType, _, _, supportsAttestationProofType, supportsJwtProofTypeWithAttestation) = resolveProofTypeAttestationSupport(proofTypesSupported: proofTypesSupported)
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: msoMdocConf.docType, vct: nil, scope: msoMdocConf.scope, supportsAttestationProofType: supportsAttestationProofType, supportsJwtProofTypeWithAttestation: supportsJwtProofTypeWithAttestation, credentialSigningAlgValuesSupported: jwtProofType?.algorithms ?? [], dpopSigningAlgValuesSupported: dpopSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported: clientAttestationPopSigningAlgValuesSupported, issuerDisplay: issuerDisplay.map(\.displayMetadata), display: msoMdocConf.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: msoMdocConf.credentialMetadata?.claims ?? [], credentialMetadata: msoMdocConf.credentialMetadata, format: .cbor, defaultCredentialOptions: try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: msoMdocConf.credentialMetadata?.credentialReusePolicy))
		} else if case let credentials = credentialsSupported.filter({ if case .sdJwtVc(let sdJwtVc) = $0.value, vct != nil || identifier != nil, sdJwtVc.vct == vct || vct == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), let credential = credentials.first(where: { !$0.key.value.hasSuffix("_deferred")}) ?? credentials.first, case let .sdJwtVc(sdJwtVc) = credential.value {
			logger.info("sdJwtVc with vct \(sdJwtVc.vct ?? ""), identifier: \(credential.key.value), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
			let proofTypesSupported = sdJwtVc.proofTypesSupported ?? [:]
			let (jwtProofType, _, _, supportsAttestationProofType, supportsJwtProofTypeWithAttestation) = resolveProofTypeAttestationSupport(proofTypesSupported: proofTypesSupported)
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: nil, vct: sdJwtVc.vct, scope: sdJwtVc.scope,  supportsAttestationProofType: supportsAttestationProofType, supportsJwtProofTypeWithAttestation: supportsJwtProofTypeWithAttestation, credentialSigningAlgValuesSupported: jwtProofType?.algorithms ?? [], dpopSigningAlgValuesSupported: dpopSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported: clientAttestationPopSigningAlgValuesSupported, issuerDisplay: issuerDisplay.map(\.displayMetadata), display: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: sdJwtVc.credentialMetadata?.claims ?? [], credentialMetadata: sdJwtVc.credentialMetadata, format: .sdjwt, defaultCredentialOptions: try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: sdJwtVc.credentialMetadata?.credentialReusePolicy))
		}
		let requestedParams = [docType.map { "docType: \($0)" }, vct.map { "vct: \($0)" }, identifier.map { "identifier: \($0)" }].compactMap { $0 }.joined(separator: ", ")
		logger.error("No credential configuration found with \(requestedParams). Available credential identifiers: \(credentialsSupported.keys.map(\.value).joined(separator: ", "))")
		throw WalletError(description: "Issuer does not support the requested credential with \(requestedParams).", code: .invalidQueryResolution)
	}

	func buildCredentialOffer(for docTypeIdentifiers: [DocTypeIdentifier]) async throws -> ([CredentialConfiguration], CredentialOffer) {
		let (credentialIssuerIdentifier, metaData) = try await resolveIssuerMetadata()
		guard let authorizationServer = metaData.authorizationServers?.first else {
			throw WalletError(description: "Invalid authorization server - no authorization server found", code: .authorizationFailed)
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		var credentialConfigurations: [CredentialConfiguration] = []
		var configurationIdentifiers: [CredentialConfigurationIdentifier] = []
		for docTypeIdentifier in docTypeIdentifiers {
			let configuration = try buildCredentialConfiguration(
				docTypeIdentifier: docTypeIdentifier,
				credentialIssuerIdentifier: credentialIssuerIdentifier,
				metaData: metaData,
				authorizationServerMetadata: authorizationServerMetadata
			)
			credentialConfigurations.append(configuration)
			configurationIdentifiers.append(configuration.configurationIdentifier)
		}
		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metaData,
			credentialConfigurationIdentifiers: configurationIdentifiers,
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)
		return (credentialConfigurations, offer)
	}

	func buildCredentialConfiguration(docTypeIdentifier: DocTypeIdentifier, credentialIssuerIdentifier: CredentialIssuerId, metaData: CredentialIssuerMetadata, authorizationServerMetadata: IdentityAndAccessManagementMetadata) throws -> CredentialConfiguration {
		try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString, issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance, dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name))
	}

	func makeOfferedDocModel(from config: CredentialConfiguration, credentialOptions: CredentialOptions?, keyOptions: KeyOptions?) -> OfferedDocModel {
		OfferedDocModel(credentialConfigurationIdentifier: config.configurationIdentifier.value, docType: config.docType, vct: config.vct, scope: config.scope ?? "", identifier: config.configurationIdentifier.value, displayName: config.display.getName(uiCulture) ?? config.docType ?? config.vct ?? config.scope ?? "", algValuesSupported: config.credentialSigningAlgValuesSupported, claims: config.claims, credentialMetadata: config.credentialMetadata, credentialOptions: credentialOptions ?? config.defaultCredentialOptions, keyOptions: keyOptions)
	}

	func getCredentialOfferedModels(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], batchCredentialIssuance: BatchCredentialIssuance?) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String?, offered: OfferedDocModel)] {
		var credentialInfos: [(identifier: CredentialConfigurationIdentifier, scope: String?, offered: OfferedDocModel)] = []
		for credential in credentialsSupported {
			if case .msoMdoc(let msoMdocCred) = credential.value {
				let dco = try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: msoMdocCred.credentialMetadata?.credentialReusePolicy)
				let offered = OfferedDocModel(credentialConfigurationIdentifier: credential.key.value, docType: msoMdocCred.docType, vct: nil, scope: msoMdocCred.scope, identifier: credential.key.value, displayName: msoMdocCred.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported, claims: msoMdocCred.credentialMetadata?.claims ?? [], credentialMetadata: msoMdocCred.credentialMetadata, credentialOptions: dco, keyOptions: nil)
				credentialInfos.append((identifier: credential.key, scope: msoMdocCred.scope, offered: offered))
			} else if case .sdJwtVc(let sdJwtVc) = credential.value {
				let dco = try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: sdJwtVc.credentialMetadata?.credentialReusePolicy)
				let offered = OfferedDocModel(credentialConfigurationIdentifier: credential.key.value, docType: nil, vct: sdJwtVc.vct, scope: sdJwtVc.scope, identifier: credential.key.value, displayName: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? "", algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported, claims: sdJwtVc.credentialMetadata?.claims ?? [], credentialMetadata: sdJwtVc.credentialMetadata, credentialOptions: dco, keyOptions: nil)
				credentialInfos.append((identifier: credential.key, scope: sdJwtVc.scope, offered: offered))
			}
		}
		return credentialInfos
	}

	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizeRequestOutcome {
		let pushedAuthorizationRequestEndpoint = if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else { "" }
		if config.parUsage.required && pushedAuthorizationRequestEndpoint.isEmpty {
			logger.info("PAR not supported, Pushed Authorization Request Endpoint is nil")
		}
		logger.info("--> [AUTHORIZATION] Placing Request to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		let parPlaced = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)

		self.authRequested = parPlaced
		logger.info("--> [AUTHORIZATION] Placed Request. Authorization code URL is: \(parPlaced.authorizationCodeURL)")
		let authResult = try await loginUserAndGetAuthCode(authorizationCodeURL: parPlaced.authorizationCodeURL.url)
		logger.info("--> [AUTHORIZATION] Authorization code retrieved")
		switch authResult {
		case .code(let authorizationCode, let serverState):
			return .authorized(try await handleAuthorizationCode(issuer: issuer, offer: offer, request: parPlaced, authorizationCode: authorizationCode, serverState: serverState))
		case .presentation_request(let url):
			return .presentation_request(url)
		}
	}

	private func handleAuthorizationCode(issuer: Issuer, offer: CredentialOffer, request: AuthorizationRequested, authorizationCode: String, serverState: String?) async throws -> AuthorizedRequest {
		let typedAuthorizationCode = try AuthorizationCode(value: authorizationCode)
		let authorized = try await issuer.authorizeWithAuthorizationCode(serverState: serverState ?? request.state, request: request, authorizationCode: typedAuthorizationCode, authorizationDetailsInTokenRequest: .doNotInclude, grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil)))
		let at = authorized.accessToken
		logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
		_ = authorized.accessToken.isExpired(issued: authorized.timeStamp, at: Date().timeIntervalSinceReferenceDate)
		return authorized
	}

	private static func submissionUseCase(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], logger: Logger) async throws -> IssuanceOutcome {
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier)
		let requestOutcome = try await issuer.requestCredential(request: authorized, bindingKeys: bindingKeys, requestPayload: payload) { Issuer.createResponseEncryptionSpec($0) }
		switch requestOutcome {
		case .success(let response):
			if let result = response.credentialResponses.first {
				switch result {
				case .deferred(let transactionId, let interval):
					logger.info("Credential issuance deferred with transactionId: \(transactionId), interval: \(interval) seconds")
					// Prepare model for deferred issuance
					let derKeyData: Data? = if let encryptionSpec = await issuer.deferredResponseEncryptionSpec, let key = encryptionSpec.privateKey { try secCall { SecKeyCopyExternalRepresentation(key, $0)} as Data } else { nil }
					let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, timeStamp: authorized.timeStamp)
					return .deferred(deferredModel, configuration, authorized)
				case .issued(_, _, let notificationId, _):
					let credentials =  response.credentialResponses.compactMap { if case let .issued(_, cr, _, _) = $0 { cr } else { nil } }
					return try await Self.handleCredentialResponse(credentials: credentials, publicKeys: publicKeys, configuration: configuration, authorized: authorized, notificationId: notificationId, logger: logger)
				}
			} else {
				throw WalletError(description: "No credential response results available", code: .issuanceRequestFailed)
			}
		case .invalidProof(let errorDescription):
			throw WalletError(description: "Issuer error: " + (errorDescription ?? "The proof is invalid"), code: .issuanceRequestFailed)
		case .failed(let error):
			throw WalletError(description: error.localizedDescription, code: .issuanceRequestFailed, innerError: error)
		}
	}

	private static func handleCredentialResponse(credentials: [Credential], publicKeys: [Data], configuration: CredentialConfiguration, authorized: AuthorizedRequest, notificationId: String?, logger: Logger) async throws -> IssuanceOutcome {
		let toData: (String) -> Data = { str in
			logger.notice(configuration.format == .cbor ? "Base64URL mdoc data:\n\(str)" : "sd-jwt credential data:\n\(str)")
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
			let response = json.enumerated().map { j in
				let str = parseJsonToJwt(j.element.1["credential"])
				return (toData(str), publicKeys[j.offset])
			}
			logger.notice("Issued credential data:\n\(String(data: response.first!.0, encoding: .utf8) ?? "")")
			return response
		} else {
			throw WalletError(description: "Invalid credential", code: .issuanceRequestFailed)
		} }
		// keep dpop key may be reused
		// if config.dpopKeyOptions != nil { try? await issueReq.secureArea.deleteKeyBatch(id: issueReq.dpopKeyId, startIndex: 0, batchSize: 1); try? await issueReq.secureArea.deleteKeyInfo(id: issueReq.dpopKeyId) }
		return .issued(credData, configuration, authorized, notificationId: notificationId)
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
		guard deferredDoc.status == .deferred else { throw WalletError(description: "Invalid document status for deferred issuance: \(deferredDoc.status)", code: .internalError) }
		let data = try await requestDeferredIssuanceInternal(deferredDoc: deferredDoc, credentialOptions: credentialOptions)
		guard case .issued(_, _, _, _) = data else { return deferredDoc }
		return try await finalizeIssuing(issueOutcome: data, docType: deferredDoc.docType, format: deferredDoc.docDataFormat, issueReq: issueReq, deleteId: nil)
	}

	func requestDeferredIssuanceInternal(deferredDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		guard let docMetadata = DocMetadata(from: deferredDoc.metadata) else {
			throw WalletError(description: "Deferred issuance document metadata is missing", code: .internalError)
		}
		let configurationIdentifier = docMetadata.configurationIdentifier
		let docTypeIdentifier: DocTypeIdentifier  = .identifier(configurationIdentifier)
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		issueReq = try IssueRequest(id: deferredDoc.id, credentialOptions: usedCredentialOptions, keyOptions: keyOptions)
		guard let authorizedRequestData = docMetadata.authorizedRequestData,
			  let decodedAuthorized = try? JSONDecoder().decode(AuthorizedRequestData.self, from: authorizedRequestData) else {
			throw WalletError(description: "Deferred issuance authorized request data is missing", code: .internalError)
		}
		let authorized = decodedAuthorized.toAuthorizedRequest()
		let dpopKeyId = docMetadata.dpopKeyId
		let (credentialConfigurations, _) = try await buildCredentialOffer(for: [.identifier(configurationIdentifier)])
		guard let configuration = credentialConfigurations.first else {
			throw WalletError(description: "Deferred issuance credential configuration could not be resolved", code: .internalError)
		}
		let deferredAction: (Bool) async throws -> IssuanceOutcome = { forceRefreshToken in
			let (issuer, dpopConstructor) = try await self.getIssuerForDeferred(data: model, configuration: configuration, dpopKeyId: dpopKeyId)
			let refreshedAuthorized = try await self.refreshAuthorization(issuer: issuer, authorized: authorized, configuration: configuration, forceRefreshToken: forceRefreshToken)
			return try await self.deferredCredentialUseCase(issuer: issuer, dpopConstructor: dpopConstructor, authorized: refreshedAuthorized, transactionId: model.transactionId, publicKeys: model.publicKeys, derKeyData: model.derKeyData, configuration: configuration)
		}
		do {
			return try await deferredAction(false)
		} catch CredentialIssuanceError.requestFailed(let code, let error, let description) where (400..<500).contains(code) {
			logger.error("Deferred issuance authentication failure with status code: \(code), error: \(error) \(description ?? "").")
			return try await deferredAction(true)
		} catch PostError.requestError(let code, let error) where (400..<500).contains(code) {
			logger.error("Deferred issuance authentication failure with status code: \(code), error: \(error).")
			return try await deferredAction(true)
		}
	}

	private func refreshAuthorization(issuer: Issuer, authorized: AuthorizedRequest, configuration: CredentialConfiguration, forceRefreshToken: Bool) async throws -> AuthorizedRequest {
		guard authorized.isAccessTokenExpired() || forceRefreshToken else { return authorized }
		if let refreshTokenExpiresIn = authorized.refreshToken?.expiresIn,
		   authorized.isRefreshTokenExpired(clock: Date.now.timeIntervalSinceReferenceDate) {
			logger.info("Issuance refresh token expired at \(Date(timeIntervalSinceReferenceDate: authorized.timeStamp + refreshTokenExpiresIn)).")
		}
		guard let algs = configuration.clientAttestationPopSigningAlgValuesSupported else { throw WalletError(description: "No client attestation POP signing algorithms found", code: .noClientAttestationAlgorithmFound) }
		let vciConfig = try await config.toOpenId4VCIConfig(
			credentialIssuerId: configuration.credentialIssuerIdentifier,
			clientAttestationPopSigningAlgValuesSupported: algs.map { JWSAlgorithm(name: $0) }
		)
		let refreshedAuthorized = try await issuer.refresh(client: vciConfig.client, authorizedRequest: authorized, dPopNonce: nil)
		logger.info("Refreshed authorized request for issuance")
		return refreshedAuthorized
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
		guard pendingDoc.status == .pending, let docTypeIdentifier = pendingDoc.docTypeIdentifier else { throw WalletError(description: "Invalid document status for pending issuance: \(pendingDoc.status)", code: .internalError)}
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(id: pendingDoc.id, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedCredentialOptions, keyOptions: keyOptions, disablePrompt: true, promptMessage: nil)
		let outcome = try await resumePendingIssuance(pendingDoc: pendingDoc, webUrl: webUrl)
		if case .pending(_) = outcome { return pendingDoc }
		let res = try await finalizeIssuing(issueOutcome: outcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: issueReq, deleteId: nil)
		return res
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else {
			throw WalletError(description: "Unknown pending reason: \(model.pendingReason)", code: .internalError)
		}
		guard let webUrl else {
			throw WalletError(description: "Web URL not specified", code: .authorizationFailed)
		}
		let asWeb = try await loginUserAndGetAuthCode(authorizationCodeURL: webUrl)
		guard case .code(let authorizationCode, let serverState) = asWeb else {
			throw WalletError(description: "Pending issuance not authorized", code: .authorizationFailed)
		}
		guard let offer = Self.credentialOfferCache[model.metadataKey] else {
			throw WalletError(description: "Pending issuance cannot be completed", code: .internalError)
		}
		let issuer = try await getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		// Append client_id if missing from the redirect URL (fixes presentation-during-issuance flow, see #376)
		var authCodeUrlString = webUrl.absoluteString
		if var components = URLComponents(url: webUrl, resolvingAgainstBaseURL: false),
		   !(components.queryItems ?? []).contains(where: { $0.name == AuthorizationCodeURL.PARAM_CLIENT_ID }) {
			var items = components.queryItems ?? []
			items.append(URLQueryItem(name: AuthorizationCodeURL.PARAM_CLIENT_ID, value: await issuer.config.client.id))
			components.queryItems = items
			if let updatedUrl = components.string { authCodeUrlString = updatedUrl }
		}
		let authorizationCodeURL = try AuthorizationCodeURL(urlString: authCodeUrlString)
		let request = AuthorizationRequested(
			credentials: [try .init(value: model.configuration.configurationIdentifier.value)],
			authorizationCodeURL: authorizationCodeURL, pkceVerifier: pkceVerifier, state: model.state,
			configurationIds: [model.configuration.configurationIdentifier]
		)
		let authorized = try await issuer.authorizeWithAuthorizationCode(
			serverState: serverState ?? request.state, request: request,
			authorizationCode: try AuthorizationCode(value: authorizationCode),
			grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))
		)
		let issuerIdentifier = offer.credentialIssuerIdentifier.url.absoluteString
		let (bindingKeys, publicKeys) = try await initSecurityKeys(model.configuration, issuer: issuerIdentifier)
		let res = try await Self.submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)
		return res
	}

	private func deferredCredentialUseCase(issuer: Issuer, dpopConstructor: DPoPConstructor?, authorized: AuthorizedRequest, transactionId: TransactionId, publicKeys: [Data], derKeyData: Data?, configuration: CredentialConfiguration) async throws -> IssuanceOutcome {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		var deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec? = nil
		if let derKeyData {
			deferredResponseEncryptionSpec = await Issuer.createResponseEncryptionSpec(issuer.issuerMetadata.credentialResponseEncryption,  privateKeyData: derKeyData)
			await issuer.setDeferredResponseEncryptionSpec(deferredResponseEncryptionSpec)
		}
		let deferredIssuanceRequester = await IssuanceRequester(issuerMetadata: issuer.issuerMetadata, poster: Poster(session: networking), dpopConstructor: dpopConstructor)
		let deferredRequestResponse = try await deferredIssuanceRequester.placeDeferredCredentialRequest(
			accessToken: authorized.accessToken, transactionId: transactionId, dPopNonce: nil, maxRetries: Constants.MAX_RETRIES, issuanceResponseEncryptionSpec: deferredResponseEncryptionSpec, encryptionSpec: nil)
		switch deferredRequestResponse {
		case .issued(let credential):
			return try await Self.handleCredentialResponse(credentials: [credential], publicKeys: publicKeys, configuration: configuration, authorized: authorized, notificationId: nil, logger: logger)
		case .issuancePending(let transactionId, let interval):
			logger.info("Credential not ready yet. Try after \(interval)")
			let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, timeStamp: authorized.timeStamp)
			return .deferred(deferredModel, configuration, authorized)
		case .issuanceStillPending(let interval):
			logger.info("Credential still not ready. Try again after \(interval)")
			let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, timeStamp: authorized.timeStamp)
			return .deferred(deferredModel, configuration, authorized)
		case .errored(_, let errorDescription):
			throw WalletError(description: "\(errorDescription ?? "Something went wrong with your deferred request response")", code: .issuanceRequestFailed)
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
					nillableContinuation?.resume(throwing: WalletError.authRequestFailed(error: error))
					nillableContinuation = nil
					return
				}
				guard let url else {
					nillableContinuation?.resume(throwing: WalletError(description: "Authorization response does not include a url", code: .authorizationFailed))
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
					let state = url.getQueryStringParameter("state")
					nillableContinuation?.resume(returning: .code(code, state: state))
					nillableContinuation = nil
				} else {
					nillableContinuation?.resume(throwing: WalletError(description: "Authorization response does not include a code", code: .authorizationFailed))
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
		throw WalletError(description: "Unable to find supported signing algorithm. Credential issuer supports: \(algSupported.map(\.rawValue)), secure area supports: \(secureAreasSupportedAlgorithms.map(\.rawValue))", code: .unsupportedAlgorithm)
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

	func finalizeIssuing(issueOutcome: IssuanceOutcome, docType: String?, format: DocDataFormat, issueReq: IssueRequest, deleteId: String?, issuer: (any IssuerType)? = nil, dpopKeyId: String? = nil, issuerName: String? = nil, issuerIdentifier: String? = nil, issuerLogoUrl: String? = nil) async throws -> WalletStorage.Document  {
		var issuedNotificationId: String? = nil
		var issuedAuthorizedRequest: AuthorizedRequest? = nil
		do {
			let savedDpopKeyId = dpopKeyId ?? issueReq.dpopKeyId
			var dataToSave: Data; var docTypeToSave = ""
			var docMetadata: DocMetadata; var displayName: String?
			let pds = issueOutcome.pendingOrDeferredStatus
			var batch: [WalletStorage.Document]?
			var publicKeys: [Data] = []
			var dkInfo = DocKeyInfo(secureAreaName: issueReq.secureAreaName, batchSize: 0, credentialPolicy: issueReq.credentialOptions.credentialPolicy)
			switch issueOutcome {
			case .issued(let dataPairs, let cc, let authorized, let notificationId):
				// Capture for potential failure notification outside switch scope
				issuedNotificationId = notificationId
				issuedAuthorizedRequest = authorized
				guard dataPairs.first != nil else { throw WalletError(description: "Empty issued data array", code: .internalError) }
				dataToSave = issueOutcome.getDataToSave(index: 0, format: format)
				docMetadata = cc.convertToDocMetadata(authorized: authorized, keyOptions: issueReq.keyOptions, credentialOptions: issueReq.credentialOptions, dpopKeyId: savedDpopKeyId)
				let docTypeOrVctOrScope = docType ?? cc.docType ?? cc.scope ?? ""
				dkInfo.batchSize = dataPairs.count
				docTypeToSave = if format == .cbor, dataToSave.count > 0 { (try IssuerSigned(data: [UInt8](dataToSave))).issuerAuth.mso.docType } else if format == .sdjwt, dataToSave.count > 0 { SdJwtUtils.getVctFromSdJwt(docData: dataToSave) ?? docTypeOrVctOrScope } else { docTypeOrVctOrScope }
				displayName = cc.display.getName(uiCulture)
				if dataPairs.count > 0 {
					batch = (0..<dataPairs.count).map { WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: issueOutcome.getDataToSave(index: $0, format: format), docKeyInfo: nil, createdAt: Date(), metadata: nil, displayName: displayName, status: .issued) }
					publicKeys = dataPairs.map(\.publicKey)
				}
			case .deferred(let deferredIssuanceModel, let cc, let authorized):
				dataToSave = try JSONEncoder().encode(deferredIssuanceModel)
				docMetadata = cc.convertToDocMetadata(authorized: authorized, keyOptions: issueReq.keyOptions, credentialOptions: issueReq.credentialOptions, dpopKeyId: savedDpopKeyId)
				docTypeToSave = docType ?? "DEFERRED"
				displayName = cc.display.getName(uiCulture)
			case .pending(let pendingAuthModel):
				dataToSave = try JSONEncoder().encode(pendingAuthModel)
				docMetadata = pendingAuthModel.configuration.convertToDocMetadata(dpopKeyId: savedDpopKeyId)
				docTypeToSave = docType ?? "PENDING"
				displayName = pendingAuthModel.configuration.display.getName(uiCulture)
			}
			// Download credential display images eagerly at issuance time.
			docMetadata = await docMetadata.downloadingDisplayImages()
			let newDocStatus: WalletStorage.DocumentStatus = issueOutcome.isDeferred ? .deferred : (issueOutcome.isPending ? .pending : .issued)
			let newDocument = WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: dataToSave, docKeyInfo: dkInfo.toData(), createdAt: Date(), metadata: docMetadata.toData(), displayName: displayName, status: newDocStatus)
			if newDocStatus == .pending { await storage.appendDocModel(newDocument, uiCulture: uiCulture); return newDocument }
			if newDocStatus == .issued { try await validateIssuedDocuments(newDocument, batch: batch, publicKeys: publicKeys) }
			if let deleteId, storage.getDocumentModel(id: deleteId) != nil { try await storage.deleteDocument(id: deleteId, status: .issued) }
			try await endIssueDocument(newDocument, batch: batch)
			await storage.appendDocModel(newDocument, uiCulture: uiCulture)
			await storage.refreshPublishedVars()
			if pds == nil { try await storage.removePendingOrDeferredDoc(id: issueReq.id) }
			await logIssuanceTransaction(status: .completed, format: format, issuerName: issuerName, issuerIdentifier: issuerIdentifier, issuerLogoUrl: issuerLogoUrl, documentId: newDocument.id, docType: newDocument.docType, docDisplayName: newDocument.displayName, docMetadata: newDocument.metadata)
			// Notify issuer of successful credential acceptance (fire-and-forget, after storage completes)
			if let notificationId = issuedNotificationId, let authorized = issuedAuthorizedRequest, let issuer {
				sendIssuanceNotification(issuer: issuer, authorized: authorized, notificationId: notificationId, event: .credentialAccepted)
			}
			return newDocument
		} catch {
			// Notify issuer of credential failure if the issuer sent a notification_id (fire-and-forget)
			if let notificationId = issuedNotificationId, let authorized = issuedAuthorizedRequest, let issuer {
				sendIssuanceNotification(issuer: issuer, authorized: authorized, notificationId: notificationId, event: .credentialFailure, eventDescription: error.localizedDescription)
			}
			await logIssuanceTransaction(status: .failed, format: format, issuerName: issuerName, issuerIdentifier: issuerIdentifier, issuerLogoUrl: issuerLogoUrl, docType: docType, errorMessage: error.localizedDescription)
			throw error
		}
	}

	private func sendIssuanceNotification(issuer: any IssuerType, authorized: AuthorizedRequest, notificationId: String, event: NotifiedEvent, eventDescription: String? = nil) {
		Task {
			do {
				let notifId = try NotificationId(value: notificationId)
				try await issuer.notify(
					authorizedRequest: authorized,
					notification: NotificationObject(id: notifId, event: event, eventDescription: eventDescription),
					dPopNonce: nil
				)
				logger.info("Issuance notification sent: \(event) [\(notificationId)]")
			} catch {
				logger.warning("Issuance notification failed (non-blocking): \(error)")
			}
		}
	}

	private func logIssuanceTransaction(status: TransactionLog.Status, format: DocDataFormat, issuerName: String?, issuerIdentifier: String?, issuerLogoUrl: String?, documentId: String? = nil, docType: String? = nil, docDisplayName: String? = nil, docMetadata: Data? = nil, errorMessage: String? = nil) async {
		guard let transactionLogger else { return }
		let issuingParty = TransactionLog.IssuingParty(name: issuerName ?? "Unknown Issuer", identifier: issuerIdentifier ?? "", logoUrl: issuerLogoUrl)
		let dataFormat = TransactionLog.DataFormat(format)
		let transactionLog = TransactionLog(timestamp: TransactionLogUtils.getTimestamp(), status: status, errorMessage: errorMessage, issuingParty: issuingParty, type: .issuance, dataFormat: dataFormat, docMetadata: docMetadata != nil ? [docMetadata] : nil, documentId: documentId, docType: docType, displayName: docDisplayName)
		do {
			try await transactionLogger.log(transaction: transactionLog)
		} catch {
			logger.error("Failed to log issuance transaction: \(error)")
		}
	}

	func validateIssuedDocuments(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?, publicKeys: [Data]) async throws {
		var pkCoseKeys = publicKeys.compactMap { try? CoseKey(data: [UInt8]($0)) }
		guard pkCoseKeys.count == publicKeys.count else { throw WalletError(description: "Failed to parse public keys", code: .internalError) }
		for doc in (batch ?? [issued]) {
			if doc.docDataFormat == .cbor {
				let iss = try IssuerSigned(data: [UInt8](doc.data))
				trustConfig.issuerTrustManager.docType = doc.docType
				try await iss.validate(docType: doc.docType, trustValidator: trustConfig.issuerTrustManager, trustPolicy: trustConfig.policy(for: doc.docType), publicCoseKeys: &pkCoseKeys)
			} else if doc.docDataFormat == .sdjwt {
				try await validateIssuedSdJwt(doc, publicCoseKeys: &pkCoseKeys)
			}
		}
	}

	private func validateIssuedSdJwt(_ document: WalletStorage.Document, publicCoseKeys: inout [CoseKey]) async throws {
		guard let serialized = String(data: document.data, encoding: .utf8) else {
			throw WalletError(description: "Failed to decode SD-JWT credential data", code: .issuanceRequestFailed)
		}
		try validateSdJwtBindingKeys(serialized, publicCoseKeys: &publicCoseKeys)
		let expectedIssuer = try expectedSdJwtIssuerURL()
		let signedSdJwt = try CompactParser().getSignedSdJwt(serialisedString: serialized)
		let hasX5c = !(signedSdJwt.jwt.protectedHeader.x509CertificateChain ?? []).isEmpty
		try validateSdJwtIssuer(serialized, expectedIssuer: expectedIssuer, requireIssuer: !hasX5c)
		let verifier = SDJWTVerifier(sdJwt: signedSdJwt)
		// Determine the issuer public key: prefer x5c certificate chain, fall back to metadata
		let issuerKey: any KeyExpressible
		if let x5cChain = signedSdJwt.jwt.protectedHeader.x509CertificateChain, !x5cChain.isEmpty {
			try await validateSdJwtIssuerTrust(x5cChain: x5cChain, docType: document.docType)
			issuerKey = try getIssuerKey(from: x5cChain)
		} else {
			let metadataFetcher = SdJwtVcIssuerMetaDataFetcher(session: URLSession.shared)
			let metadata = try await metadataFetcher.fetchIssuerMetaData(issuer: expectedIssuer)
			guard let kid = signedSdJwt.jwt.protectedHeader.keyID else {
				throw WalletError(description: "Issued SD-JWT is missing both x5c chain and key identifier", code: .issuanceRequestFailed)
			}
			guard let issuerJwk = metadata?.jwks.first(where: { $0.keyID == kid }) else {
				throw WalletError(description: "Unable to resolve issuer signing key for issued SD-JWT", code: .trustError)
			}
			issuerKey = issuerJwk
		}
		let result = try verifier.verifyIssuance(
			issuersSignatureVerifier: { jws in try SignatureVerifier(signedJWT: jws, publicKey: issuerKey) },
			claimVerifier: { nbf, exp in ClaimsVerifier(nbf: nbf, exp: exp) }
		)
		try validateVerificationResult(result)
	}

	private func validateSdJwtBindingKeys(_ serialized: String, publicCoseKeys: inout [CoseKey]) throws {
		let cnfKeys = try SdJwtUtils.parseCnfBindingKeys(fromSerializedCredential: serialized)
		let availableKeys = publicCoseKeys.map(\.x963Representation)
		for key in cnfKeys {
			guard let x = Data(base64URLEncoded: key.x), let y = Data(base64URLEncoded: key.y) else {
				throw WalletError(description: "Issued SD-JWT cnf JWK has invalid key coordinates", code: .issuanceRequestFailed)
			}
			let keyX963 = MdocDataModel18013.CoseKey.x963Representation(x: x, y: y)
			let index = availableKeys.firstIndex(of: keyX963)
			if let index {
				publicCoseKeys.remove(at: index)
			} else {
				throw WalletError(description: "Failed to find matching public key for SD-JWT cnf binding key", code: .issuanceRequestFailed)
			}
		}
	}

	private func validateVerificationResult(_ result: Result<SignedSDJWT, any Error>) throws {
		guard case .success = result else {
			let error = switch result {
			case .failure(let error): error
			case .success: WalletError(description: "Unexpected SD-JWT verification result", code: .internalError)
			}
			throw error
		}
	}

	private func expectedSdJwtIssuerURL() throws -> URL {
		guard let issuer = config.credentialIssuerURL, let issuerURL = URL(string: issuer) else {
			throw WalletError(description: "credentialIssuerURL must be a valid URL to verify SD-JWT credentials", code: .internalError)
		}
		return issuerURL
	}

	private func validateSdJwtIssuer(_ serialized: String, expectedIssuer: URL, requireIssuer: Bool = true) throws {
		let (_, payload, _) = SdJwtUtils.extractJWTParts(serialized)
		guard let payloadData = Data(base64URLEncoded: payload) else {
			throw WalletError(description: "Failed to decode SD-JWT payload", code: .issuanceRequestFailed)
		}
		let payloadJson = try JSON(data: payloadData)
		guard let issuer = payloadJson["iss"].string else {
			if requireIssuer { throw WalletError(description: "Issued SD-JWT is missing a valid issuer", code: .issuanceRequestFailed) }
			return // If issuer is not required, skip validation
		}
		guard let issuerURL = URL(string: issuer) else {
			throw WalletError(description: "Issued SD-JWT is missing a valid issuer", code: .issuanceRequestFailed)
		}
		if normalized(url: issuerURL) != normalized(url: expectedIssuer) {
			logger.warning("Issued SD-JWT issuer \(issuerURL.absoluteString) does not match expected issuer \(expectedIssuer.absoluteString)")
		}
	}
	/// Returns the public key from the leaf certificate.
	private func getIssuerKey(from x5cChain: [String]) throws -> SecKey {
		let certsData = x5cChain.compactMap { Data(base64Encoded: $0) }
		guard certsData.count == x5cChain.count else {
			throw WalletError(description: "Invalid base64 encoding in SD-JWT x5c certificate chain", code: .issuanceRequestFailed)
		}
		let secCerts = certsData.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		guard secCerts.count == certsData.count else {
			throw WalletError(description: "Failed to parse certificates in SD-JWT x5c chain", code: .issuanceRequestFailed)
		}
		// Extract public key from the leaf certificate
		guard let secKey = SecCertificateCopyKey(secCerts[0]) else {
			throw WalletError(description: "Unable to extract public key from SD-JWT x5c leaf certificate", code: .issuanceRequestFailed)
		}
		return secKey
	}

	/// Validates the issued SD-JWT's x5c certificate chain against the configured issuer trust manager.
	/// Honors the doc-type trust policy: `.enforce` throws on an untrusted chain, `.warning` only logs.
	private func validateSdJwtIssuerTrust(x5cChain: [String], docType: String) async throws {
		let chainData = x5cChain.compactMap { Data(base64Encoded: $0) }
		guard chainData.count == x5cChain.count else {
			throw WalletError(description: "Invalid base64 encoding in SD-JWT x5c certificate chain", code: .issuanceRequestFailed)
		}
		trustConfig.issuerTrustManager.docType = docType
		let (trusted, reason) = await trustConfig.issuerTrustManager.validateCertTrustPath(chain: chainData)
		guard trusted else {
			var message = "Issued SD-JWT issuer certificate chain is not trusted"
			if let reason { message += ": \(reason)" }
			if trustConfig.policy(for: docType) == .enforce { throw WalletError(description: message, code: .trustError) }
			return
		}
	}

	private func normalized(url: URL) -> String {
		let absoluteString = url.absoluteString
		return absoluteString.hasSuffix("/") ? String(absoluteString.dropLast()) : absoluteString
	}
	func hasIssuerUrl(_ issuerURL: String) -> Bool {
		guard let configURL = config.credentialIssuerURL else { return false }
		// Normalize by removing trailing slashes for comparison
		let normalizedConfig = configURL.hasSuffix("/") ? String(configURL.dropLast()) : configURL
		let normalizedInput = issuerURL.hasSuffix("/") ? String(issuerURL.dropLast()) : issuerURL
		return normalizedConfig == normalizedInput
	}

} // end of OpenId4VCIService

fileprivate extension URL {
	func getQueryStringParameter(_ parameter: String) -> String? {
		guard let url = URLComponents(string: self.absoluteString) else { return nil }
		return url.queryItems?.first(where: { $0.name == parameter })?.value
	}
}

extension WalletError {
	public static func authRequestFailed(error: Error) -> WalletError {
		if let wae = error as? ASWebAuthenticationSessionError {
			if wae.code == .canceledLogin { return WalletError(description: "The login has been cancelled.", localizationKey: "login_cancelled", code: .userCancelledLogin, innerError: wae)  }
			else if wae.code == .presentationContextNotProvided { return WalletError(description: "Web authentication presentation context not provided.", code: .authorizationFailed, innerError: wae) }
			else if wae.code == .presentationContextInvalid { return WalletError(description: "Web authentication presentation context invalid.", code: .authorizationFailed, innerError: wae) }
			else { return WalletError(description: wae.localizedDescription, code: .authorizationFailed, innerError: wae) }
		}
		return WalletError(description:"Authorization request failed: \(error.localizedDescription)", code: .authorizationFailed, innerError: error)

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

extension Array where Element == OpenId4VciService {
	public func getByIssuerURL(_ issuerURL: String) async -> OpenId4VciService? {
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
	private var services: [String: OpenId4VciService] = [:]
	private let lock = NSRecursiveLock()

	private init() {}

	public func register(name: String, service: OpenId4VciService) {
		lock.lock()
		defer { lock.unlock() }
		services[name] = service
	}

	public func get(name: String) -> OpenId4VciService? {
		lock.lock()
		defer { lock.unlock() }
		return services[name]
	}

	public func getAllNames() -> [String] {
		lock.lock()
		defer { lock.unlock() }
		return Array(services.keys)
	}

	public func getAllServices() -> [OpenId4VciService] {
		lock.lock()
		defer { lock.unlock() }
		return Array(services.values)
	}

	public func getByIssuerURL(issuerURL: String) async -> OpenId4VciService? {
		return await getAllServices().getByIssuerURL(issuerURL)
	}
}
