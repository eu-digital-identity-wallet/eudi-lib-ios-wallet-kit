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
@preconcurrency import OpenID4VCI
import JOSESwift
import MdocDataModel18013
import AuthenticationServices
import Logging
import CryptoKit
import Security
import WalletStorage
import SwiftCBOR
import JOSESwift

extension CredentialIssuerSource: @retroactive @unchecked Sendable {}

public final class OpenId4VCIService: NSObject, @unchecked Sendable, ASWebAuthenticationPresentationContextProviding {
	let issueReq: IssueRequest
	let credentialIssuerURL: String
	let uiCulture: String?
	var bindingKey: BindingKey!
	let logger: Logger
	let config: OpenId4VCIConfig
	static var metadataCache = [String: CredentialOffer]()
	var urlSession: URLSession
	var parRequested: ParRequested?

	init(issueRequest: IssueRequest, credentialIssuerURL: String, uiCulture: String?, config: OpenId4VCIConfig, urlSession: URLSession) {
		self.issueReq = issueRequest
		self.credentialIssuerURL = credentialIssuerURL
		self.uiCulture = uiCulture
		self.urlSession = urlSession
		logger = Logger(label: "OpenId4VCI")
		self.config = config
	}

	func initSecurityKeys(algSupported: Set<String>) async throws {
		let crvType = issueReq.keyOptions?.curve ?? type(of: issueReq.secureArea).defaultEcCurve
		let secureAreaSigningAlg: SigningAlgorithm = crvType.defaultSigningAlgorithm
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
		guard !algTypes.isEmpty, let algType = JWSAlgorithm.AlgorithmType(rawValue: secureAreaSigningAlg.rawValue), algTypes.contains(algType) else {
			throw WalletError(description: "Unable to find supported signing algorithm \(secureAreaSigningAlg)")
		}
		let publicCoseKey = try await issueReq.createKey()
		let publicKey: SecKey = try publicCoseKey.toSecKey()
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": JWSAlgorithm(algType).name, "use": "sig", "kid": UUID().uuidString])
		let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		bindingKey = .jwk(algorithm: JWSAlgorithm(algType), jwk: publicKeyJWK, privateKey: .custom(signer) , issuer: config.client.id)
	}

	func setBindingKey(bindingKey: BindingKey) {
		self.bindingKey = bindingKey
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
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher(session: urlSession), credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession))).resolve(source: try .init(urlString: uriOffer))
		switch result {
		case .success(let offer):
			let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
			Self.metadataCache[uriOffer] = offer
			let credentialInfo = try getCredentialIdentifiers(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) })
			let issuerName = offer.credentialIssuerMetadata.display.getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: "")
			let issuerLogoUrl = offer.credentialIssuerMetadata.display.getLogo(uiCulture)?.uri?.absoluteString
			return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
		case .failure(let error):
			throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	func getIssuer(offer: CredentialOffer) throws -> Issuer {
		try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession))
	}

	func getIssuerForDeferred(data: DeferredIssuanceModel) throws -> Issuer {
		try Issuer.createDeferredIssuer(deferredCredentialEndpoint: data.deferredCredentialEndpoint, deferredRequesterPoster: Poster(session: urlSession), config: config)
	}

	func authorizeOffer(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String?) async throws -> (AuthorizeRequestOutcome, [CredentialConfiguration]) {
		guard let offer = Self.metadataCache[offerUri] else { throw WalletError(description: "offerUri not resolved. resolveOfferDocTypes must be called first")}
		let credentialInfos = docTypeModels.compactMap { try? getCredentialIdentifier(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, scope: $0.scope) }
		guard credentialInfos.count > 0, credentialInfos.count == docTypeModels.count else { throw WalletError(description: "Missing Credential identifiers") }
		try await initSecurityKeys(algSupported: Set(credentialInfos.flatMap { $0.algValuesSupported }))
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode):	preAuthorizedCode; case .both(_, let preAuthorizedCode):	preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try getIssuer(offer: offer)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil { throw WalletError(description: "A transaction code is required for this offer") }
		let authorizedOutcome = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) { AuthorizeRequestOutcome.authorized(try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: config.client, transactionCode: txCodeValue).get()) } else { try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer) }
		return (authorizedOutcome, credentialInfos)
	}

	func issueDocumentByOfferUrl(offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome? {
		if case .presentation_request(let url) = authorizedOutcome, let parRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.metadataCache[uuid] = offer
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: parRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: parRequested.pkceVerifier.codeVerifierMethod ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
		do {
			let id = configuration.configurationIdentifier.value; let sc = configuration.scope; let dn = configuration.display.getName(uiCulture) ?? ""
			logger.info("Starting issuing with identifer \(id), scope \(sc), displayName: \(dn)")
			let issuer = try getIssuer(offer: offer)
			let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: configuration, claimSet: claimSet)
			// logger.info("Credential str:\n\(str)")
			return res
		} catch {
			// logger.error("Failed to issue document with scope \(ci.scope)")
			logger.info("Exception: \(error)")
			return nil
		}
	}

	func issueByDocType(_ docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
		switch issuerMetadata {
		case .success(let metaData):
			if let authorizationServer = metaData.authorizationServers?.first {
				let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
				let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
				try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
				// Authorize with auth code flow
				let issuer = try getIssuer(offer: offer)
				let authorizedOutcome = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
				if case .presentation_request(let url) = authorizedOutcome, let parRequested {
					logger.info("Dynamic issuance request with url: \(url)")
					let uuid = UUID().uuidString
					Self.metadataCache[uuid] = offer
					let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: parRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: parRequested.pkceVerifier.codeVerifierMethod ))
					return (outcome, configuration.format)
				}
				guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
				let outcome = try await issueOfferedCredentialInternal(authorized, issuer: issuer, configuration: configuration, claimSet: claimSet)
				return (outcome, configuration.format)
			} else {
				throw WalletError(description: "Invalid authorization server")
			}
		case .failure:
			throw WalletError(description: "Invalid issuer metadata")
		}
	}

	private func issueOfferedCredentialInternal(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, claimSet: ClaimSet?) async throws -> IssuanceOutcome {
		switch authorized {
		case .noProofRequired:
			return try await noProofRequiredSubmissionUseCase(issuer: issuer, noProofRequiredState: authorized, configuration: configuration, claimSet: claimSet)
		case .proofRequired:
			return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, configuration: configuration, claimSet: claimSet)
		}
	}

	private func issueOfferedCredentialInternalValidated(_ authorized: AuthorizedRequest, offer: CredentialOffer, issuer: Issuer, configuration: CredentialConfiguration, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		let issuerMetadata = offer.credentialIssuerMetadata
		guard issuerMetadata.credentialsSupported.keys.contains(where: { $0.value == configuration.configurationIdentifier.value }) else {
			throw WalletError(description: "Cannot find credential identifier \(configuration.configurationIdentifier.value) in offer")
		}
		return try await issueOfferedCredentialInternal(authorized, issuer: issuer, configuration: configuration, claimSet: claimSet)
	}

	func getCredentialIdentifier(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, scope: String?) throws -> CredentialConfiguration {
			if let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope {
			logger.info("msoMdoc with scope \(scope), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
				return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: docType, scope: scope, display: msoMdocConf.display.map(\.displayMetadata), issuerDisplay: issuerDisplay.map(\.displayMetadata), algValuesSupported: msoMdocConf.proofTypesSupported?["jwt"]?.algorithms ?? [], msoClaims: msoMdocConf.claims, flatClaims: nil, order: msoMdocConf.order, format: .cbor)
		} else if let credential =  credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtVc) = $0.value, sdJwtVc.scope == scope || scope == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .sdJwtVc(sdJwtVc) = credential.value, let scope = sdJwtVc.scope {
			logger.info("sdJwtVc with scope \(scope), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: docType, scope: scope, display: sdJwtVc.display.map(\.displayMetadata), issuerDisplay: issuerDisplay.map(\.displayMetadata), algValuesSupported: sdJwtVc.proofTypesSupported?["jwt"]?.algorithms ?? [], msoClaims: nil, flatClaims: sdJwtVc.claims, order: nil, format: .sdjwt)
		}
		logger.error("No credential for docType \(docType ?? scope ?? identifier ?? ""). Currently supported credentials: \(credentialsSupported.keys)")
		throw WalletError(description: "Issuer does not support docType or scope or identifier \(docType ?? scope ?? identifier ?? "")")
	}

	func getCredentialIdentifiers(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported]) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
			let credentialInfos = credentialsSupported.compactMap {
				if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: msoMdocCred.docType, scope: scope, displayName: msoMdocCred.display.getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported) { (identifier: $0.key, scope: scope, offered: offered) }
				else if case .sdJwtVc(let sdJwtVc) = $0.value, let scope = sdJwtVc.scope, case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: nil, scope: scope, displayName: sdJwtVc.display.getName(uiCulture) ?? scope, algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported) { (identifier: $0.key, scope: scope, offered: offered) }
				else { nil } }
			return credentialInfos
	}

	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizeRequestOutcome {
		var pushedAuthorizationRequestEndpoint = ""
		if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
		} else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
		}
		guard !pushedAuthorizationRequestEndpoint.isEmpty else { throw WalletError(description: "pushed Authorization Request Endpoint is nil") }
		logger.info("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		let parPlaced = try await issuer.pushAuthorizationCodeRequest(credentialOffer: offer)

		if case let .success(request) = parPlaced, case let .par(parRequested) = request {
			self.parRequested = parRequested
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			let authResult = try await loginUserAndGetAuthCode(getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url)
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

	private func handleAuthorizationCode(issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
		let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request)
			if case let .success(authorized) = authorizedRequest, case let .noProofRequired(token, _, _, _, _) = authorized {
				let at = token.accessToken;	logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
				return authorized
			}
			throw WalletError(description: "Failed to get access token")
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}

	private func noProofRequiredSubmissionUseCase(issuer: Issuer, noProofRequiredState: AuthorizedRequest, configuration: CredentialConfiguration, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		switch noProofRequiredState {
		case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp, _):
			let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier,	claimSet: claimSet)
			let responseEncryptionSpecProvider =  { @Sendable in Issuer.createResponseEncryptionSpec($0) }
			let requestOutcome = try await issuer.request(noProofRequest: noProofRequiredState, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
			switch requestOutcome {
			case .success(let request):
				switch request {
				case .success(let response):
					if let result = response.credentialResponses.first {
						switch result {
						case .deferred(let transactionId):
							let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
							return .deferred(deferredModel)
						case .issued(let format, let credential, _, _):
							return try handleCredentialResponse(credential: credential, format: format, configuration: configuration)
						}
					} else {
						throw WalletError(description: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
					return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), configuration: configuration, claimSet: claimSet)
				case .failed(error: let error):
					throw WalletError(description: error.localizedDescription)
				}
			case .failure(let error):
				throw WalletError(description: error.localizedDescription)
			}
		default: throw WalletError(description: "Illegal noProofRequiredState case")
		}
	}

	private func handleCredentialResponse(credential: Credential, format: String?, configuration: CredentialConfiguration) throws -> IssuanceOutcome {
		logger.info("Credential issued with format \(format ?? "unknown")")
		if case let .string(str) = credential  {
			// logger.info("Issued credential data:\n\(strBase64)")
			return .issued(Data(base64URLEncoded: str), str, configuration)
		} else if case let .json(json) = credential {
			return .issued(try JSONEncoder().encode(json), nil, configuration)
		} else {
			throw WalletError(description: "Invalid credential")
		}
	}

	private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, configuration: CredentialConfiguration?, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		guard case .proofRequired(let accessToken, let refreshToken, _, _, let timeStamp, _) = authorized else { throw WalletError(description: "Unexpected AuthorizedRequest case") }
		guard let configuration else { throw WalletError(description: "Credential configuration not found") }
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier, claimSet: claimSet)
		let responseEncryptionSpecProvider = { @Sendable in Issuer.createResponseEncryptionSpec($0) }
		let requestOutcome = try await issuer.request(proofRequest: authorized, bindingKeys: [bindingKey], requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId):
						let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
						return .deferred(deferredModel)
					case .issued(let format, let credential, _, _):
						return try handleCredentialResponse(credential: credential, format: format, configuration: configuration)
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

	func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try getIssuerForDeferred(data: model)
		let authorized: AuthorizedRequest = .noProofRequired(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil, timeStamp: model.timeStamp, dPopNonce: nil)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId, configuration: model.configuration)
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }
		guard let webUrl else { throw WalletError(description: "Web URL not specified") }
		let asWeb = try await loginUserAndGetAuthCode(getAuthorizationCodeUrl: webUrl)
		guard case .code(let authorizationCode) = asWeb else { throw WalletError(description: "Pending issuance not authorized") }
		guard let offer = Self.metadataCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		let issuer = try getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.authorizeWithAuthorizationCode(authorizationCode: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil))).get()
		try await initSecurityKeys(algSupported: Set(model.configuration.algValuesSupported))
		let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: model.configuration, claimSet: nil)
		Self.metadataCache.removeValue(forKey: model.metadataKey)
		return res
	}

	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId, configuration: CredentialConfiguration) async throws -> IssuanceOutcome {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId, dPopNonce: nil)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(let credential):
				return try handleCredentialResponse(credential: credential, format: nil, configuration: configuration)
			case .issuancePending(let transactionId):
				logger.info("Credential not ready yet. Try after \(transactionId.interval ?? 0)")
				let deferredModel = switch authorized {
				case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp, _):
					await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
				case .proofRequired(let accessToken, let refreshToken, _, _, let timeStamp, _):
					await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
				}
				return .deferred(deferredModel)
			case .errored(_, let errorDescription):
				throw WalletError(description: "\(errorDescription ?? "Something went wrong with your deferred request response")")
			}
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}

	@MainActor
	private func loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL) async throws -> AsWebOutcome {
		let lock = NSLock()
		return try await withCheckedThrowingContinuation { continuation in
			var nillableContinuation: CheckedContinuation<AsWebOutcome, Error>? = continuation
			let authenticationSession = ASWebAuthenticationSession(url: getAuthorizationCodeUrl, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { url, error in
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


