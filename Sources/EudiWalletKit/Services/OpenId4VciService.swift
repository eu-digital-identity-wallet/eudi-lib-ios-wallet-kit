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

public class OpenId4VCIService: NSObject, ASWebAuthenticationPresentationContextProviding {
	let issueReq: IssueRequest
	let credentialIssuerURL: String
	var privateKey: SecKey!
	var publicKey: SecKey!
	var bindingKey: BindingKey!
	var usedSecureEnclave: Bool!
	let logger: Logger
	let config: OpenId4VCIConfig
	let alg = JWSAlgorithm(.ES256)
	static var metadataCache = [String: CredentialOffer]()
	var urlSession: URLSession
	
	init(issueRequest: IssueRequest, credentialIssuerURL: String, clientId: String, callbackScheme: String, urlSession: URLSession) {
		self.issueReq = issueRequest
		self.credentialIssuerURL = credentialIssuerURL
		self.urlSession = urlSession
		logger = Logger(label: "OpenId4VCI")
		config = .init(clientId: clientId, authFlowRedirectionURI: URL(string: callbackScheme)!)
	}
	
	fileprivate func initSecurityKeys(_ useSecureEnclave: Bool) throws {
		usedSecureEnclave = useSecureEnclave && SecureEnclave.isAvailable
		if !usedSecureEnclave {
			let key = try P256.KeyAgreement.PrivateKey(x963Representation: issueReq.keyData)
			privateKey = try key.toSecKey()
		} else {
			let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: issueReq.keyData)
			privateKey = try seKey.toSecKey()
		}
		publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey,additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
		bindingKey = .jwk(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKey, issuer: config.clientId)
	}
	
	/// Issue a document with the given `docType` using OpenId4Vci protocol
	/// - Parameters:
	///   - docType: the docType of the document to be issued
	///   - format: format of the exchanged data
	///   - useSecureEnclave: use secure enclave to protect the private key
	/// - Returns: The data of the document
	func issueDocument(docType: String, format: DataFormat, useSecureEnclave: Bool = true) async throws -> IssuanceOutcome {
		try initSecurityKeys(useSecureEnclave)
		let res = try await issueByDocType(docType, format: format)
		return res
	}
	
	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(uriOffer: String, format: DataFormat = .cbor) async throws -> OfferedIssuanceModel {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher(session: urlSession), credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession))).resolve(source: try .init(urlString: uriOffer))
		switch result {
		case .success(let offer):
			let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode):	preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
			Self.metadataCache[uriOffer] = offer
			let credentialInfo = try getCredentialIdentifiers(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, format: format)
			return OfferedIssuanceModel(issuerName: offer.credentialIssuerIdentifier.url.absoluteString, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
		case .failure(let error):
			throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}
	
	func getIssuer(offer: CredentialOffer) throws -> Issuer {
		try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession))
	}
	
	func getIssuerForDeferred(data: DeferredIssuanceModel) throws -> Issuer {
		try Issuer(authorizationServerMetadata: .oauth(AuthorizationServerMetadata(issuer: nil, authorizationEndpoint: nil, tokenEndpoint: nil, introspectionEndpoint: nil, jwksURI: nil, grantTypesSupported: nil, responseTypesSupported: nil, requestObjectSigningAlgValuesSupported: nil, requestObjectEncryptionAlgValuesSupported: nil, requestObjectEncryptionEncValuesSupported: nil, responseModesSupported: nil, registrationEndpoint: nil, tokenEndpointAuthMethodsSupported: nil, tokenEndpointAuthSigningAlgValuesSupported: nil, introspectionEndpointAuthMethodsSupported: nil, introspectionEndpointAuthSigningAlgValuesSupported: nil, authorizationSigningAlgValuesSupported: nil, authorizationEncryptionAlgValuesSupported: nil, authorizationEncryptionEncValuesSupported: nil, scopesSupported: nil, requestParameterSupported: nil, requestURIParameterSupported: nil, requireRequestURIRegistration: nil, codeChallengeMethodsSupported: nil, tlsClientCertificateBoundAccessTokens: nil, dpopSigningAlgValuesSupported: nil, revocationEndpoint: nil, revocationEndpointAuthMethodsSupported: nil, revocationEndpointAuthSigningAlgValuesSupported: nil, deviceAuthorizationEndpoint: nil, backchannelTokenDeliveryModesSupported: nil, backchannelAuthenticationEndpoint: nil, backchannelAuthenticationRequestSigningAlgValuesSupported: nil, requirePushedAuthorizationRequests: nil, pushedAuthorizationRequestEndpoint: nil, mtlsEndpointAliases: nil, authorizationResponseIssParameterSupported: nil)), issuerMetadata: CredentialIssuerMetadata(credentialIssuerIdentifier: CredentialIssuerId(""), authorizationServers: [], credentialEndpoint: data.deferredCredentialEndpoint, batchCredentialEndpoint: nil, deferredCredentialEndpoint: data.deferredCredentialEndpoint, notificationEndpoint: nil, credentialConfigurationsSupported: [:], signedMetadata: nil, display: nil), config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession))
	}
	
	func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String?, format: DataFormat, useSecureEnclave: Bool = true, claimSet: ClaimSet? = nil) async throws -> [IssuanceOutcome] {
		guard format == .cbor else { throw fatalError("jwt format not implemented") }
		try initSecurityKeys(useSecureEnclave)
		guard let offer = Self.metadataCache[offerUri] else { throw WalletError(description: "offerUri not resolved. resolveOfferDocTypes must be called first")}
		let credentialInfo = docTypes.compactMap { try? getCredentialIdentifier(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, docType: $0.docType, format: format)
		}
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode):	preAuthorizedCode; case .both(_, let preAuthorizedCode):	preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try getIssuer(offer: offer)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil { throw WalletError(description: "A transaction code is required for this offer") }
		let authorized = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) { try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, clientId: config.clientId, transactionCode: txCodeValue).get() } else { try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer) }
		let data = await credentialInfo.asyncCompactMap {
			do {
				logger.info("Starting issuing with identifer \($0.identifier.value) and scope \($0.scope)")
				let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, credentialConfigurationIdentifier: $0.identifier, claimSet: claimSet)
				// logger.info("Credential str:\n\(str)")
				return res
			} catch {
				logger.error("Failed to issue document with scope \($0.scope)")
				logger.info("Exception: \(error)")
				return nil
			}
		}
		Self.metadataCache.removeValue(forKey: offerUri)
		return data
	}
	
	func issueByDocType(_ docType: String, format: DataFormat, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
		switch issuerMetadata {
		case .success(let metaData):
			if let authorizationServer = metaData?.authorizationServers.first, let metaData {
				let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
				let (credentialConfigurationIdentifier, _) = try getCredentialIdentifier(credentialsSupported: metaData.credentialsSupported, docType: docType, format: format)
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [credentialConfigurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
				// Authorize with auth code flow
				let issuer = try getIssuer(offer: offer)
				let authorized = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
				return try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
			} else {
				throw WalletError(description: "Invalid authorization server")
			}
		case .failure:
			throw WalletError(description: "Invalid issuer metadata")
		}
	}
	
	private func issueOfferedCredentialInternal(_ authorized: AuthorizedRequest, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet?) async throws -> IssuanceOutcome {
		switch authorized {
		case .noProofRequired:
			return try await noProofRequiredSubmissionUseCase(issuer: issuer, noProofRequiredState: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
		case .proofRequired:
			return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
		}
	}
	
	private func issueOfferedCredentialInternalValidated(_ authorized: AuthorizedRequest, offer: CredentialOffer, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		let issuerMetadata = offer.credentialIssuerMetadata
		guard issuerMetadata.credentialsSupported.keys.contains(where: { $0.value == credentialConfigurationIdentifier.value }) else {
			throw WalletError(description: "Cannot find credential identifier \(credentialConfigurationIdentifier.value) in offer")
		}
		return try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
	}
	
	func getCredentialIdentifier(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], docType: String, format: DataFormat) throws -> (identifier: CredentialConfigurationIdentifier, scope: String) {
		switch format {
		case .cbor:
			guard let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope else {
				logger.error("No credential for docType \(docType). Currently supported credentials: \(credentialsSupported.values)")
				throw WalletError(description: "Issuer does not support doc type\(docType)")
			}
			logger.info("Currently supported cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			return (identifier: credential.key, scope: scope)
		default:
			throw WalletError(description: "Format \(format) not yet supported")
		}
	}
	
	func getCredentialIdentifier(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], scope: String, format: DataFormat) throws -> (identifier: CredentialConfigurationIdentifier, scope: String) {
		switch format {
		case .cbor:
			guard let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.scope == scope { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope else {
				logger.error("No credential for scope \(scope). Currently supported credentials: \(credentialsSupported.values)")
				throw WalletError(description: "Issuer does not support scope \(scope)")
			}
			logger.info("Currently supported cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			return (identifier: credential.key, scope: scope)
		default:
			throw WalletError(description: "Format \(format) not yet supported")
		}
	}
	
	func getCredentialIdentifiers(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], format: DataFormat) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
		switch format {
		case .cbor:
			let credentialInfos = credentialsSupported.compactMap {
				if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let offered = OfferedDocModel(docType: msoMdocCred.docType, displayName: msoMdocCred.display.getName() ?? msoMdocCred.docType) { (identifier: $0.key, scope: scope,offered: offered) } else { nil } }
			return credentialInfos
		default:
			throw WalletError(description: "Format \(format) not yet supported")
		}
	}
	
	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizedRequest {
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
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			let authorizationCode = try await loginUserAndGetAuthCode(
				getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url) ?? { throw WalletError(description: "Could not retrieve authorization code") }()
			logger.info("--> [AUTHORIZATION] Authorization code retrieved")
			let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
			switch unAuthorized {
			case .success(let request):
				let authorizedRequest = await issuer.requestAccessToken(authorizationCode: request)
				if case let .success(authorized) = authorizedRequest, case let .noProofRequired(token, _, _) = authorized {
					logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(token.accessToken)")
					return authorized
				}
			case .failure(let error):
				throw  WalletError(description: error.localizedDescription)
			}
		} else if case let .failure(failure) = parPlaced {
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}
	
	private func noProofRequiredSubmissionUseCase(issuer: Issuer, noProofRequiredState: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		switch noProofRequiredState {
		case .noProofRequired(let accessToken, let refreshToken, _):
			let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: credentialConfigurationIdentifier,	claimSet: claimSet)
			let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
			let requestOutcome = try await issuer.requestSingle(noProofRequest: noProofRequiredState, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
			switch requestOutcome {
			case .success(let request):
				switch request {
				case .success(let response):
					if let result = response.credentialResponses.first {
						switch result {
						case .deferred(let transactionId):
							//return try await deferredCredentialUseCase(issuer: issuer, authorized: noProofRequiredState, transactionId: transactionId)
							let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId)
							return .deferred(deferredModel)
						case .issued(_, let credential, _):
							guard let data = Data(base64URLEncoded: credential) else { throw WalletError(description: "Invalid credential")	}
							return .issued(data)
						}
					} else {
						throw WalletError(description: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
					return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), credentialConfigurationIdentifier: credentialConfigurationIdentifier)
				case .failed(error: let error):
					throw WalletError(description: error.localizedDescription)
				}
			case .failure(let error):
				throw WalletError(description: error.localizedDescription)
			}
		default: throw WalletError(description: "Illegal noProofRequiredState case")
		}
	}
	
	private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier?, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		guard case .proofRequired(let accessToken, let refreshToken, let cNonce, let credentialIdentifiers) = authorized else { throw WalletError(description: "Unexpected AuthorizedRequest case") }
		guard let credentialConfigurationIdentifier else { throw WalletError(description: "Credential configuration identifier not found") }
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
		let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
		let requestOutcome = try await issuer.requestSingle(proofRequest: authorized, bindingKey: bindingKey, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId):
						//return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: transactionId)
						let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId)
						return .deferred(deferredModel)
					case .issued(_, let credential, _):
						guard let data = Data(base64URLEncoded: credential) else { throw WalletError(description: "Invalid credential")	}
						return .issued(data)
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
		let model: DeferredIssuanceModel = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try getIssuerForDeferred(data: model)
		let authorized: AuthorizedRequest = .noProofRequired(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId)
	}
	
	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId) async throws -> IssuanceOutcome {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(_, let credential):
				guard let data = Data(base64URLEncoded: credential) else { throw WalletError(description: "Invalid credential")	}
				return .issued(data)
			case .issuancePending(let transactionId):
				logger.info("Credential not ready yet. Try after \(transactionId.interval ?? 0)")
				let deferredModel = switch authorized {
				case .noProofRequired(let accessToken, let refreshToken, _):
					await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId)
				case .proofRequired(let accessToken, let refreshToken, _, _):
					await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId)
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
	private func loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL) async throws -> String? {
		return try await withCheckedThrowingContinuation { c in
			let authenticationSession = ASWebAuthenticationSession(url: getAuthorizationCodeUrl, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { optionalUrl, optionalError in
				guard optionalError == nil else { c.resume(throwing: OpenId4VCIError.authRequestFailed(optionalError!)); return }
				guard let url = optionalUrl else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl); return }
				guard let code = url.getQueryStringParameter("code") else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoCode); return }
				c.resume(returning: code)
			}
			authenticationSession.prefersEphemeralWebBrowserSession = true
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

extension SecureEnclave.P256.KeyAgreement.PrivateKey {
	
	func toSecKey() throws -> SecKey {
		var errorQ: Unmanaged<CFError>?
		guard let sf = SecKeyCreateWithData(Data() as NSData, [
			kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeyClass: kSecAttrKeyClassPrivate,
			kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
			"toid": dataRepresentation
		] as NSDictionary, &errorQ) else { throw errorQ!.takeRetainedValue() as Error }
		return sf
	}
}

extension P256.KeyAgreement.PrivateKey {
	func toSecKey() throws -> SecKey {
		var error: Unmanaged<CFError>?
		guard let privateKey = SecKeyCreateWithData(x963Representation as NSData, [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, &error) else {
			throw error!.takeRetainedValue() as Error
		}
		return privateKey
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


