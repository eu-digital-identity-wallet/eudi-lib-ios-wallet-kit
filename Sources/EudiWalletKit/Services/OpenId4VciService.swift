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
	static var metadataCache = [String: CredentialOffer]()
	var networking: Networking
	var authRequested: AuthorizationRequested?
	var keyBatchSize: Int { issueReq.keyOptions?.batchSize ?? 1 }

	init(issueRequest: IssueRequest, credentialIssuerURL: String, uiCulture: String?, config: OpenId4VCIConfig, networking: Networking) {
		self.issueReq = issueRequest
		self.credentialIssuerURL = credentialIssuerURL
		self.uiCulture = uiCulture
		self.networking = networking
		logger = Logger(label: "OpenId4VCI")
		self.config = config
	}

	func initSecurityKeys(algSupported: Set<String>) async throws -> [BindingKey] {
		let crvType = issueReq.keyOptions?.curve ?? type(of: issueReq.secureArea).defaultEcCurve
		let secureAreaSigningAlg: MdocDataModel18013.SigningAlgorithm = crvType.defaultSigningAlgorithm
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
		guard !algTypes.isEmpty, let algType = JWSAlgorithm.AlgorithmType(rawValue: secureAreaSigningAlg.rawValue), algTypes.contains(algType) else {
			throw WalletError(description: "Unable to find supported signing algorithm \(secureAreaSigningAlg)")
		}
		let publicCoseKeys = try await issueReq.createKeyBatch()
		let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
		let bindingKeys = try publicCoseKeys.enumerated().map { try createBindingKey($0.element, secureAreaSigningAlg: secureAreaSigningAlg, unlockData: unlockData, index: $0.offset) }
		return bindingKeys
	}

	func createBindingKey(_ publicCoseKey: CoseKey, secureAreaSigningAlg: MdocDataModel18013.SigningAlgorithm, unlockData: Data?, index: Int) throws -> BindingKey {
		let publicKey: SecKey = try publicCoseKey.toSecKey()
		let algType = JWSAlgorithm.AlgorithmType(rawValue: secureAreaSigningAlg.rawValue)!
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": JWSAlgorithm(algType).name, "use": "sig", "kid": UUID().uuidString])
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, index: index, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		let bindingKey: BindingKey = .jwk(algorithm: JWSAlgorithm(algType), jwk: publicKeyJWK, privateKey: .custom(signer), issuer: config.client.id)
		return bindingKey
	}

	func createKeyBatch() async throws {
		_ = try await issueReq.createKeyBatch()
	}

	static func removeOfferFromMetadata(offerUri: String) {
		Self.metadataCache.removeValue(forKey: offerUri)
	}

	/// Issue a document with the given `docType` or `scope` or `identifier` using OpenId4Vci protocol
	/// - Parameters:
	///   - docType: the docType of the document to be issued
	///   - scope: the scope of the document to be issued
	///   - identifier: the credential configuration identifier of the document to be issued
	/// - Returns: The data of the document
	func issueDocument(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope or identifier must be provided") }
		logger.log(level: .info, "Issuing document with \(docType != nil ? "docType" : scope != nil ? "scope" : "identifier"): \(docTypeOrScopeOrIdentifier)")
		let res = try await issueByDocType(docType, scope: scope, identifier: identifier, promptMessage: promptMessage)
		return res
	}

	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(uriOffer: String) async throws -> OfferedIssuanceModel {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher(session: networking), credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(fetcher: Fetcher(session: networking)), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: networking), oauthFetcher: Fetcher(session: networking))).resolve(source: try .init(urlString: uriOffer), policy: .ignoreSigned)
		switch result {
		case .success(let offer):
			let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
			Self.metadataCache[uriOffer] = offer
			let credentialInfo = try getCredentialOfferedModels(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance)
			let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: "")
			let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
			return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
		case .failure(let error):
			throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	func getDefaultKeyOptions(batchCredentialIssuance: BatchCredentialIssuance?) -> KeyOptions {
		let batchCredentialIssuanceSize = if let batchCredentialIssuance { batchCredentialIssuance.batchSize } else { 1 }
		return KeyOptions(credentialPolicy: .rotateUse, batchSize: batchCredentialIssuanceSize)
	}

	func getDefaultKeyOptions(_ docType: String?, scope: String?, identifier: String?) async throws -> KeyOptions {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		let credentialConfiguration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope, batchCredentialIssuance: metaData.batchCredentialIssuance)
		return credentialConfiguration.defaultKeyOptions
	}

	func getIssuer(offer: CredentialOffer) throws -> Issuer {
		try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: networking), tokenPoster: Poster(session: networking), requesterPoster: Poster(session: networking), deferredRequesterPoster: Poster(session: networking), notificationPoster: Poster(session: networking))
	}

	func getIssuerForDeferred(data: DeferredIssuanceModel) throws -> Issuer {
		try Issuer.createDeferredIssuer(deferredCredentialEndpoint: data.deferredCredentialEndpoint, deferredRequesterPoster: Poster(session: networking), config: config)
	}

	func authorizeOffer(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String?) async throws -> (AuthorizeRequestOutcome, [CredentialConfiguration]) {
		guard let offer = Self.metadataCache[offerUri] else { throw WalletError(description: "offerUri not resolved. resolveOfferDocTypes must be called first")}
		let credentialInfos = docTypeModels.compactMap { try? getCredentialConfiguration(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, scope: $0.scope, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance) }
		guard credentialInfos.count > 0, credentialInfos.count == docTypeModels.count else { throw WalletError(description: "Missing Credential identifiers") }
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try getIssuer(offer: offer)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil { throw WalletError(description: "A transaction code is required for this offer") }
		let authorizedOutcome = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) { AuthorizeRequestOutcome.authorized(try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: config.client, transactionCode: txCodeValue).get()) } else { try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer) }
		return (authorizedOutcome, credentialInfos)
	}

	func issueDocumentByOfferUrl(offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, bindingKeys: [BindingKey], promptMessage: String? = nil) async throws -> IssuanceOutcome? {
		if case .presentation_request(let url) = authorizedOutcome, let authRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.metadataCache[uuid] = offer
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
		do {
			let id = configuration.configurationIdentifier.value; let sc = configuration.scope; let dn = configuration.display.getName(uiCulture) ?? ""
			logger.info("Starting issuing with identifer \(id), scope \(sc ?? ""), displayName: \(dn)")
			let issuer = try getIssuer(offer: offer)
			let res = try await submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys)
			// logger.info("Credential str:\n\(str)")
			return res
		} catch {
			// logger.error("Failed to issue document with scope \(ci.scope)")
			logger.info("Exception: \(error)")
			return nil
		}
	}

	func getIssuerMetadata() async throws -> (CredentialIssuerId, CredentialIssuerMetadata) {
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = try await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: networking)).resolve(source: .credentialIssuer(credentialIssuerIdentifier), policy: config.issuerMetadataPolicy)
		switch issuerMetadata {
		case .success(let metaData):
			return (credentialIssuerIdentifier, metaData)
		case .failure(let error):
			throw WalletError(description: "Failed to resolve issuer metadata: \(error.localizedDescription)")
		}
	}

	func issueByDocType(_ docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		let (credentialIssuerIdentifier, metaData) = try await getIssuerMetadata()
		if let authorizationServer = metaData.authorizationServers?.first {
			let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: networking), oauthFetcher: Fetcher(session: networking)).resolve(url: authorizationServer)
			let configuration = try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope, batchCredentialIssuance: metaData.batchCredentialIssuance)
			let bindingKeys = try await initSecurityKeys(algSupported: Set(configuration.credentialSigningAlgValuesSupported))
			let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
			// Authorize with auth code flow
			let issuer = try getIssuer(offer: offer)
			let authorizedOutcome = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
			if case .presentation_request(let url) = authorizedOutcome, let authRequested {
				logger.info("Dynamic issuance request with url: \(url)")
				let uuid = UUID().uuidString
				Self.metadataCache[uuid] = offer
				let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod ))
				return (outcome, configuration.format)
			}
			guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
			let outcome = try await submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys)
			return (outcome, configuration.format)
		} else {
			throw WalletError(description: "Invalid authorization server")
		}
	}

	func getCredentialConfiguration(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, scope: String?, batchCredentialIssuance: BatchCredentialIssuance?) throws -> CredentialConfiguration {
			if let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope {
			logger.info("msoMdoc with scope \(scope), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: msoMdocConf.docType, vct: nil, scope: scope, credentialSigningAlgValuesSupported: msoMdocConf.proofTypesSupported?["jwt"]?.algorithms ?? [], issuerDisplay: issuerDisplay.map(\.displayMetadata), display: msoMdocConf.display.map(\.displayMetadata), claims: msoMdocConf.claims, format: .cbor, defaultKeyOptions: getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance))
		} else if let credential =  credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtVc) = $0.value, sdJwtVc.scope == scope || scope == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .sdJwtVc(sdJwtVc) = credential.value, let scope = sdJwtVc.scope {
			logger.info("sdJwtVc with scope \(scope), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: nil, vct: sdJwtVc.vct, scope: scope, credentialSigningAlgValuesSupported: sdJwtVc.proofTypesSupported?["jwt"]?.algorithms ?? [], issuerDisplay: issuerDisplay.map(\.displayMetadata), display: sdJwtVc.display.map(\.displayMetadata), claims: sdJwtVc.claims, format: .sdjwt, defaultKeyOptions: getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance))
		}
		logger.error("No credential for docType \(docType ?? scope ?? identifier ?? ""). Currently supported credentials: \(credentialsSupported.keys)")
		throw WalletError(description: "Issuer does not support docType or scope or identifier \(docType ?? scope ?? identifier ?? "")")
	}

	func getCredentialOfferedModels(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], batchCredentialIssuance: BatchCredentialIssuance?) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
			let credentialInfos = credentialsSupported.compactMap {
				if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let dko = getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance), case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: msoMdocCred.docType, vct: nil, scope: scope, identifier: $0.key.value, displayName: msoMdocCred.display.map(\.displayMetadata).getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported, keyOptions: dko) { (identifier: $0.key, scope: scope, offered: offered) }
				else if case .sdJwtVc(let sdJwtVc) = $0.value, let scope = sdJwtVc.scope, case let dko = getDefaultKeyOptions(batchCredentialIssuance: batchCredentialIssuance), case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: nil, vct: sdJwtVc.vct, scope: scope, identifier: $0.key.value, displayName: sdJwtVc.display.map(\.displayMetadata).getName(uiCulture) ?? scope, algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported, keyOptions: dko) { (identifier: $0.key, scope: scope, offered: offered) }
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
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}

	private func handleAuthorizationCode(issuer: Issuer, request: AuthorizationRequestPrepared, authorizationCode: String) async throws -> AuthorizedRequest {
		let unAuthorized = await issuer.handleAuthorizationCode(request: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(request: request)
			if case let .success(authorized) = authorizedRequest {
				let at = authorized.accessToken
				logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
				return authorized
			}
			throw WalletError(description: "Failed to get access token")
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}

	private func submissionUseCase(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, bindingKeys: [BindingKey]) async throws -> IssuanceOutcome {
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier)
		let requestOutcome = try await issuer.requestCredential(request: authorized, bindingKeys: bindingKeys, requestPayload: payload) { Issuer.createResponseEncryptionSpec($0) }

		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId):
						guard let encryptionSpec = await issuer.deferredResponseEncryptionSpec, let key = encryptionSpec.privateKey else { throw ValidationError.error(reason: "Encryption specification not available")}
						let derKeyData = try secCall { SecKeyCopyExternalRepresentation(key, $0)} as Data
						let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: authorized.accessToken, refreshToken: authorized.refreshToken, transactionId: transactionId, derKeyData: derKeyData, configuration: configuration, timeStamp: authorized.timeStamp)
						return .deferred(deferredModel)
					case .issued(let format, _, _, _):
						let credentials =  response.credentialResponses.compactMap { if case let .issued(_, cr, _, _) = $0 { cr } else { nil } }
						return try handleCredentialResponse(credentials: credentials, format: format, configuration: configuration)
					}
				} else {
					throw WalletError(description: "No credential response results available")
				}
			case .invalidProof:
				throw WalletError(description: "Although providing a proof with c_nonce the proof is still invalid")
			case .failed(let error):
				throw WalletError(description: error.localizedDescription)
			}
		case .failure(let error): throw WalletError(description: error.localizedDescription)
		}
	}

	private func handleCredentialResponse(credentials: [Credential], format: String?, configuration: CredentialConfiguration) throws -> IssuanceOutcome {
		logger.info("Credential issued with format \(format ?? "unknown")")
		let credData: [(Data?, String?)] = try credentials.flatMap {
		if case let .string(str) = $0  {
			// logger.info("Issued credential data:\n\(str)")
			return [(Data(base64URLEncoded: str), str)]
		} else if case let .json(json) = $0, json.type == .array, json.first != nil {
			// logger.info("Issued credential data:\n\(json.first!.1["credential"].stringValue)")
			return json.map { j in let str = j.1["credential"].stringValue; return (Data(base64URLEncoded: str), str) }
		} else {
			throw WalletError(description: "Invalid credential")
		} }
		return .issued(credData, configuration)
	}

	func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try getIssuerForDeferred(data: model)
		let authorized = AuthorizedRequest(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil, timeStamp: model.timeStamp, dPopNonce: nil)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId, derKeyData: model.derKeyData, configuration: model.configuration)
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }
		guard let webUrl else { throw WalletError(description: "Web URL not specified") }
		let asWeb = try await loginUserAndGetAuthCode(authorizationCodeURL: webUrl)
		guard case .code(let authorizationCode) = asWeb else { throw WalletError(description: "Pending issuance not authorized") }
		guard let offer = Self.metadataCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		let issuer = try getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.authorizeWithAuthorizationCode(request: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil))).get()
		let bindingKeys = try await initSecurityKeys(algSupported: Set(model.configuration.credentialSigningAlgValuesSupported))
		let res = try await submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys)
		Self.metadataCache.removeValue(forKey: model.metadataKey)
		return res
	}

	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId, derKeyData: Data, configuration: CredentialConfiguration) async throws -> IssuanceOutcome {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredResponseEncryptionSpec = await Issuer.createResponseEncryptionSpec(issuer.issuerMetadata.credentialResponseEncryption, privateKeyData: derKeyData)
		await issuer.setDeferredResponseEncryptionSpec(deferredResponseEncryptionSpec)
		let deferredRequestResponse = try await issuer.requestDeferredCredential(request: authorized, transactionId: transactionId, dPopNonce: nil)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(let credential):
				return try handleCredentialResponse(credentials: [credential], format: nil, configuration: configuration)
			case .issuancePending(let transactionId):
				logger.info("Credential not ready yet. Try after \(transactionId.interval ?? 0)")
				let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: authorized.accessToken, refreshToken: authorized.refreshToken, transactionId: transactionId, derKeyData: derKeyData, configuration: configuration, timeStamp: authorized.timeStamp)
				return .deferred(deferredModel)
			case .errored(_, let errorDescription):
				throw WalletError(description: "\(errorDescription ?? "Something went wrong with your deferred request response")")
			}
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
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
					self.logger.info("Dynamic issuance url: \(url)")
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

	public func presentationAnchor(for session: ASWebAuthenticationSession)
	-> ASPresentationAnchor {
#if os(iOS)
		let window = UIApplication.shared.windows.first { $0.isKeyWindow }
		return window ?? ASPresentationAnchor()
#else
		return ASPresentationAnchor()
#endif
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
