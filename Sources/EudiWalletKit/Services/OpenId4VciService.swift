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

public final class OpenId4VCIService: NSObject, @unchecked Sendable, ASWebAuthenticationPresentationContextProviding {
	var issueReq: IssueRequest
	let credentialIssuerURL: String
	let uiCulture: String?
	let logger: Logger
	let config: OpenId4VCIConfig
	static var credentialOfferCache = [String: CredentialOffer]()
	static var issuerMetadataCache = [String: (CredentialIssuerId, CredentialIssuerMetadata)]()
	var networking: Networking
	var authRequested: AuthorizationRequested?
	var keyBatchSize: Int { issueReq.keyOptions?.batchSize ?? 1 }
	let cacheIssuerMetadata: Bool

	init(issueRequest: IssueRequest, credentialIssuerURL: String, uiCulture: String?, config: OpenId4VCIConfig, cacheIssuerMetadata: Bool, networking: Networking) {
		self.issueReq = issueRequest
		self.credentialIssuerURL = credentialIssuerURL
		self.uiCulture = uiCulture
		self.networking = networking
		self.cacheIssuerMetadata = cacheIssuerMetadata
		logger = Logger(label: "OpenId4VCI")
		self.config = config
	}

	// create batch keys and return the binding keys and the `CoseKey` public keys in cbor format
	func initSecurityKeys(algSupported: Set<String>) async throws -> ([BindingKey], [Data]) {
		// Convert credential issuer supported algorithms to JWSAlgorithm types
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
		guard !algTypes.isEmpty else {
			throw PresentationSession.makeError(str: "No valid signing algorithms found in credential metadata: \(algSupported)")
		}
		// Find a compatible signing algorithm that both the secure area and credential issuer support
		let selectedAlgorithm = try findCompatibleSigningAlgorithm(algSupported: algTypes)
		let publicCoseKeys = try await issueReq.createKeyBatch()
		let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
		let bindingKeys = try publicCoseKeys.enumerated().map { try createBindingKey($0.element, secureAreaSigningAlg: selectedAlgorithm, unlockData: unlockData, index: $0.offset) }
		return (bindingKeys, publicCoseKeys.map { Data($0.toCBOR(options: CBOROptions()).encode()) })
	}

	func createBindingKey(_ publicCoseKey: CoseKey, secureAreaSigningAlg: MdocDataModel18013.SigningAlgorithm, unlockData: Data?, index: Int) throws -> BindingKey {
		let publicKey: SecKey = try publicCoseKey.toSecKey()
		guard let algType = Self.mapToJWSAlgorithmType(secureAreaSigningAlg) else {
			throw PresentationSession.makeError(str: "Unsupported secure area signing algorithm: \(secureAreaSigningAlg)")
		}
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": JWSAlgorithm(algType).name, "use": "sig", "kid": UUID().uuidString])
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, index: index, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		let bindingKey: BindingKey = .jwk(algorithm: JWSAlgorithm(algType), jwk: publicKeyJWK, privateKey: .custom(signer), issuer: config.client.id)
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
	/// Issue a document with the given `DocTypeIdentifier` using OpenId4Vci protocol
	/// - Parameters:
	///   - docTypeIdentifier: the document type identifier specifying the type of document to be issued
	///   - promptMessage: optional message to prompt the user during issuance
	/// - Returns: The data of the document
	func issueDocument(docTypeIdentifier: DocTypeIdentifier, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		logger.log(level: .info, "Issuing document with identifier: \(docTypeIdentifier.value)")
		let res = try await issueByDocType(docTypeIdentifier, promptMessage: promptMessage)
		return res
	}

	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(uriOffer: String, offer: CredentialOffer) async throws -> OfferedIssuanceModel {
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		Self.credentialOfferCache[uriOffer] = offer
		let credentialInfo = try getCredentialOfferedModels(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance)
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: "")
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
	}

	func getDefaultKeyOptions(batchCredentialIssuance: BatchCredentialIssuance?) -> KeyOptions {
		let batchCredentialIssuanceSize = if let batchCredentialIssuance { batchCredentialIssuance.batchSize } else { 1 }
		return KeyOptions(credentialPolicy: .rotateUse, batchSize: batchCredentialIssuanceSize)
	}

	func getMetadataDefaultKeyOptions(_ docTypeIdentifier: DocTypeIdentifier) async throws -> KeyOptions {
		let (_, metaData) = try await getIssuerMetadata()
		return KeyOptions(credentialPolicy: .rotateUse, batchSize: metaData.batchCredentialIssuance?.batchSize ?? 1)
	}

	func getIssuer(offer: CredentialOffer) throws -> Issuer {
		try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: networking), tokenPoster: Poster(session: networking), requesterPoster: Poster(session: networking), deferredRequesterPoster: Poster(session: networking), notificationPoster: Poster(session: networking), noncePoster: Poster(session: networking), dpopConstructor: try OpenId4VCIConfiguration.makeDPoPConstructor(algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported))

	}

	func getIssuerForDeferred(data: DeferredIssuanceModel) throws -> Issuer {
		try Issuer.createDeferredIssuer(deferredCredentialEndpoint: data.deferredCredentialEndpoint, deferredRequesterPoster: Poster(session: networking), config: config)
	}

	func authorizeOffer(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String?) async throws -> (AuthorizeRequestOutcome, Issuer, [CredentialConfiguration]) {
		guard let offer = Self.credentialOfferCache[offerUri] else {
			throw PresentationSession.makeError(str: "offerUri \(offerUri) not resolved. resolveOfferDocTypes must be called first")
		}
		let credentialInfos = docTypeModels.compactMap { try? getCredentialConfiguration(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.vct, vct: $0.vct, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance) }
		guard credentialInfos.count > 0, credentialInfos.count == docTypeModels.count else {
			throw PresentationSession.makeError(str: "Missing Credential identifiers - expected: \(docTypeModels.count), found: \(credentialInfos.count)")
		}
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try getIssuer(offer: offer)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil {
			throw PresentationSession.makeError(str: "A transaction code is required for this offer")
		}
		let authorizedOutcome = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) { AuthorizeRequestOutcome.authorized(try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: config.client, transactionCode: txCodeValue).get()) } else { try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer) }
		return (authorizedOutcome, issuer, credentialInfos)
	}

	func issueDocumentByOfferUrl(issuer: Issuer, offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], promptMessage: String? = nil) async throws -> IssuanceOutcome? {
		if case .presentation_request(let url) = authorizedOutcome, let authRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.credentialOfferCache[uuid] = offer
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else {
			throw PresentationSession.makeError(str: "Invalid authorized request outcome")
		}
		do {
			let id = configuration.configurationIdentifier.value; let sc = configuration.scope; let dn = configuration.display.getName(uiCulture) ?? ""
			logger.info("Starting issuing with identifer \(id), scope \(sc ?? ""), displayName: \(dn)")
			//let issuer = try getIssuer(offer: offer)
			let res = try await submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys, publicKeys: publicKeys)
			// logger.info("Credential str:\n\(str)")
			return res
		} catch {
			// logger.error("Failed to issue document with scope \(ci.scope)")
			logger.info("Exception: \(error)")
			return nil
		}
	}

	func makeMetadataResolver() -> CredentialIssuerMetadataResolver {
	 CredentialIssuerMetadataResolver(fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: networking), processor: MetadataProcessor()))
	}

	func getIssuerMetadata() async throws -> (CredentialIssuerId, CredentialIssuerMetadata) {
		// Check cache first
		if cacheIssuerMetadata, let cachedResult = Self.issuerMetadataCache[credentialIssuerURL] {
			return cachedResult
		}
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = try await makeMetadataResolver().resolve(source: .credentialIssuer(credentialIssuerIdentifier), policy: config.issuerMetadataPolicy)
		switch issuerMetadata {
		case .success(let metaData):
			let result = (credentialIssuerIdentifier, metaData)
			if cacheIssuerMetadata { Self.issuerMetadataCache[credentialIssuerURL] = result }
			return result
		case .failure(let error):
			throw PresentationSession.makeError(str: "Failed to resolve issuer metadata: \(error.localizedDescription)")
		}
	}

	func issueByDocType(_ docTypeIdentifier: DocTypeIdentifier, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		if let authorizationServer = metaData.authorizationServers?.first {
			let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
			let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance)
			let (bindingKeys, publicKeys) = try await initSecurityKeys(algSupported: Set(configuration.credentialSigningAlgValuesSupported))
			let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
			// Authorize with auth code flow
			let issuer = try getIssuer(offer: offer)
			let authorizedOutcome = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
			if case .presentation_request(let url) = authorizedOutcome, let authRequested {
				logger.info("Dynamic issuance request with url: \(url)")
				let uuid = UUID().uuidString
				Self.credentialOfferCache[uuid] = offer
				let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))
				return (outcome, configuration.format)
			}
			guard case .authorized(let authorized) = authorizedOutcome else {
				throw PresentationSession.makeError(str: "Invalid authorized request outcome")
			}
			let outcome = try await submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys, publicKeys: publicKeys)
			return (outcome, configuration.format)
		} else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}
	}

	func getCredentialConfiguration(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, vct: String?, batchCredentialIssuance: BatchCredentialIssuance?) throws -> CredentialConfiguration {
			if let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope {
			logger.info("msoMdoc with scope \(scope), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: msoMdocConf.docType, vct: nil, scope: scope, credentialSigningAlgValuesSupported: msoMdocConf.proofTypesSupported?["jwt"]?.algorithms ?? [], issuerDisplay: issuerDisplay.map(\.displayMetadata), display: msoMdocConf.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: msoMdocConf.credentialMetadata?.claims ?? [], format: .cbor, defaultKeyOptions: getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance))
		} else if let credential =  credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtVc) = $0.value, sdJwtVc.vct == vct || vct == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .sdJwtVc(sdJwtVc) = credential.value, let scope = sdJwtVc.scope {
			logger.info("sdJwtVc with scope \(scope), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: nil, vct: sdJwtVc.vct, scope: scope, credentialSigningAlgValuesSupported: sdJwtVc.proofTypesSupported?["jwt"]?.algorithms ?? [], issuerDisplay: issuerDisplay.map(\.displayMetadata), display: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: sdJwtVc.credentialMetadata?.claims ?? [], format: .sdjwt, defaultKeyOptions: getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance))
		}
		logger.error("No credential for docType \(docType ?? vct ?? identifier ?? ""). Currently supported credentials: \(credentialsSupported.keys)")
		throw WalletError(description: "Issuer does not support docType or scope or identifier \(docType ?? vct ?? identifier ?? "")")
	}

	func getCredentialOfferedModels(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], batchCredentialIssuance: BatchCredentialIssuance?) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
			let credentialInfos = credentialsSupported.compactMap {
				if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let dko = getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance), case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: msoMdocCred.docType, vct: nil, scope: scope, identifier: $0.key.value, displayName: msoMdocCred.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported, keyOptions: dko) { (identifier: $0.key, scope: scope, offered: offered) }
				else if case .sdJwtVc(let sdJwtVc) = $0.value, let scope = sdJwtVc.scope, case let dko = getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance), case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: nil, vct: sdJwtVc.vct, scope: scope, identifier: $0.key.value, displayName: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? scope, algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported, keyOptions: dko) { (identifier: $0.key, scope: scope, offered: offered) }
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
				return .authorized(try await handleAuthorizationCode(issuer: issuer, request: request, authorizationCode: authorizationCode))
			case .presentation_request(let url):
				return .presentation_request(url)
			}
		} else if case let .failure(failure) = parPlaced {
			throw PresentationSession.makeError(str: "Authorization error: \(failure.localizedDescription)")
		}
		throw PresentationSession.makeError(str: "Failed to get push authorization code request")
	}

	private func handleAuthorizationCode(issuer: Issuer, request: AuthorizationRequestPrepared, authorizationCode: String) async throws -> AuthorizedRequest {
		let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
		let unAuthorized = await issuer.handleAuthorizationCode(request: request, authorizationCode: issuanceAuthorization)
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(request: request, authorizationDetailsInTokenRequest: .doNotInclude)
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

	private func submissionUseCase(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data]) async throws -> IssuanceOutcome {
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
						return try handleCredentialResponse(credentials: credentials, publicKeys: publicKeys, format: format, configuration: configuration)
					}
				} else {
					throw PresentationSession.makeError(str: "No credential response results available")
				}
			case .invalidProof:
				throw PresentationSession.makeError(str: "Although providing a proof with c_nonce the proof is still invalid")
			case .failed(let error):
				throw PresentationSession.makeError(str: error.localizedDescription)
			}
		case .failure(let error):
			throw PresentationSession.makeError(str: "Credential submission use case failed: \(error.localizedDescription)")
		}
	}

	private func handleCredentialResponse(credentials: [Credential], publicKeys: [Data], format: String?, configuration: CredentialConfiguration) throws -> IssuanceOutcome {
		logger.info("Credential issued with format \(format ?? "unknown")")
		let toData: (String) -> Data = { str in
			if configuration.format == .cbor { return Data(base64URLEncoded: str) ?? Data() } else { return str.data(using: .utf8) ?? Data() }
		}
		let credData: [(Data, Data)] = try credentials.enumerated().flatMap { index, credential in
		if case let .string(str) = credential  {
			// logger.info("Issued credential data:\n\(str)")
			return [(toData(str), publicKeys[index])]
		} else if case let .json(json) = credential, json.type == .array, json.first != nil {
			// logger.info("Issued credential data:\n\(json.first!.1["credential"].stringValue)")
			return json.map { j in let str = j.1["credential"].stringValue; return (toData(str), publicKeys[index]) }
		} else {
			throw PresentationSession.makeError(str: "Invalid credential")
		} }
		return .issued(credData, configuration)
	}

	func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try getIssuerForDeferred(data: model)
		let authorized = AuthorizedRequest(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil, timeStamp: model.timeStamp, dPopNonce: nil)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId, publicKeys: model.publicKeys, derKeyData: model.derKeyData, configuration: model.configuration)
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
		let issuer = try getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.authorizeWithAuthorizationCode(request: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil))).get()
		let (bindingKeys, publicKeys) = try await initSecurityKeys(algSupported: Set(model.configuration.credentialSigningAlgValuesSupported))
		let res = try await submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys, publicKeys: publicKeys)
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
				return try handleCredentialResponse(credentials: [credential], publicKeys: publicKeys, format: nil, configuration: configuration)
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
		let lock = NSLock()
		return try await withCheckedThrowingContinuation { continuation in
			var nillableContinuation: CheckedContinuation<AsWebOutcome, Error>? = continuation
			let authenticationSession = ASWebAuthenticationSession(url: authorizationCodeURL, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { url, error in
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
			authenticationSession.presentationContextProvider = self
			authenticationSession.start()
		}
	}

	public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
#if os(iOS)
		let window = UIApplication.shared.windows.first { $0.isKeyWindow }
		return window ?? ASPresentationAnchor()
#else
		return ASPresentationAnchor()
#endif
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
			issueReq.keyOptions = KeyOptions(curve: curve, credentialPolicy: .rotateUse, batchSize: 1)
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

}

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
			if let wae = error as? ASWebAuthenticationSessionError, wae.code == .canceledLogin { return "The login has been canceled." }
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
