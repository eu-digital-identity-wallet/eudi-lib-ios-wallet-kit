//
//  OpenId4VCIService.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 20.12.24.
//

import Foundation
@preconcurrency import OpenID4VCI
import MdocDataModel18013
import CryptorECC
import JOSESwift
import WalletStorage

extension OpenId4VCIService {
	
	func issuePAR(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, wia: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome, DocDataFormat) {
		guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope must be provided") }
		logger.log(level: .info, "Issuing document with docType or scope or identifier: \(docTypeOrScopeOrIdentifier)")
		let res = try await issueByPARType(docType, scope: scope, identifier: identifier, promptMessage: promptMessage, wia: wia)
		return res
	}
	
	func issuePARs(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, wia: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome, DocDataFormat) {
		guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope must be provided") }
		logger.log(level: .info, "Issuing document with docType or scope or identifier: \(docTypeOrScopeOrIdentifier)")
		let res = try await issueByPARType(docType, scope: scope, identifier: identifier, promptMessage: promptMessage, wia: wia)
		return res
	}
	
	func getCredentials(dpopNonce: String, code: String, scope: String?, claimSet: ClaimSet? = nil, identifier: String?, docType: String?, issuerDPopConstructorParam: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome?, DocDataFormat?, AuthorizedRequestParams?) {
		do {
			if let key = OpenId4VCIService.metadataCache.keys.first,
			   let offer = OpenId4VCIService.metadataCache[key],
			   let unauthorizedRequest = OpenId4VCIService.parReqCache {
				
				let dpopConstructor = DPoPConstructor(algorithm: alg, jwk: issuerDPopConstructorParam.jwk, privateKey: .secKey(issuerDPopConstructorParam.privateKey))
				let issuer = try await getIssuer(offer: offer, with: dpopConstructor)
				
				let authReq = try await handleAuthorizationCodeBothCases(issuer: issuer, request: unauthorizedRequest, authorizationCode: code)
				
				if offer.credentialConfigurationIdentifiers.first != nil {
					do {
						let configuration = try  getCredentialIdentifier(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: nil, docType: docType, scope: scope)
						
						try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
						
						let issuanceOutcome = try await issueOfferedCredentialInternal(authReq, issuer: issuer, configuration: configuration, claimSet: claimSet)
						
						let authReqParams = converAuthorizedRequestToParam(authorizedRequest: authReq)
						return (issuanceOutcome, configuration.format, authReqParams)
					} catch {
						throw WalletError(description: "Invalid issuer metadata")
					}
				}
			}
		} catch  {
			throw WalletError(description: "Invalid issuer metadata")
		}
		return (nil, nil, nil)
	}
	
	
	func resumePendingIssuance(pendingDoc: WalletStorage.Document, authorizationCode: String, issuerDPopConstructorParam: IssuerDPoPConstructorParam) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }

		guard let offer = Self.metadataCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		
		let dpopConstructor = DPoPConstructor(algorithm: alg, jwk: issuerDPopConstructorParam.jwk, privateKey: .secKey(issuerDPopConstructorParam.privateKey))
		let issuer = try await getIssuer(offer: offer, with: dpopConstructor)
		
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.authorizeWithAuthorizationCode(authorizationCode: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil))).get()
		try await initSecurityKeys(algSupported: Set(model.configuration.algValuesSupported))
		let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: model.configuration, claimSet: nil)
		Self.metadataCache.removeValue(forKey: model.metadataKey)
		return res
	}
	
	func getCredentialsWithRefreshToken(_ docType: String?, scope: String?, claimSet: ClaimSet?, identifier: String?, authorizedRequest: AuthorizedRequest, issuerDPopConstructorParam: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome?, DocDataFormat?, AuthorizedRequestParams?) {
		let dpopConstructor = DPoPConstructor(algorithm: alg, jwk: issuerDPopConstructorParam.jwk, privateKey: .secKey(issuerDPopConstructorParam.privateKey))
		do {
			let issuerInfo = try await fetchIssuerAndOfferWithLatestMetadata(docType, scope: scope, identifier: identifier, dpopConstructor: dpopConstructor)
			if let issuer = issuerInfo.0, let offer = issuerInfo.1 {
				
				let result = await issuer.refresh(clientId: config.client.id, authorizedRequest: authorizedRequest, dPopNonce: nil)
				switch result {
				case .success(let authReq):
					
					if offer.credentialConfigurationIdentifiers.first != nil {
						do {
							let configuration = try  getCredentialIdentifier(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: nil, docType: docType, scope: scope)
							
							try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
							
							let issuanceOutcome = try await issueOfferedCredentialInternal(authReq, issuer: issuer, configuration: configuration, claimSet: claimSet)
							
							let authReqParams = converAuthorizedRequestToParam(authorizedRequest: authReq)
							return (issuanceOutcome, configuration.format, authReqParams)
						} catch {
							print("Invalid issuer metadata 1")
							throw WalletError(description: "Invalid issuer metadata")
						}
					}
				case .failure(let error):
					print("Error refreshing token: \(error)")
					print("Invalid issuer metadata 2")
					throw WalletError(description: "Invalid issuer metadata")
				}
			}
		} catch {
			print("Invalid issuer metadata 3")
			throw WalletError(description: "Invalid issuer metadata")
		}
		return (nil, nil, nil)
	}
	
	private func issueByPARType(_ docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, claimSet: ClaimSet? = nil, wia: IssuerDPoPConstructorParam) async throws -> (IssuanceOutcome, DocDataFormat) {
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
		print("issuerMetadata: \(issuerMetadata)")
		switch issuerMetadata {
		case .success(let metaData):
			print("issuerMetadata: \(metaData)")
			if let authorizationServer = metaData.authorizationServers?.first {
				let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
				let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
//				try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
				
				let dPopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: wia.jwk, privateKey: .secKey(wia.privateKey))
				// Authorize with auth code flow
				let issuer = try await getIssuer(offer: offer, with: dPopConstructor)
				
				let authorizedOutcome = (try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer, wia: wia)).1
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
	
	private func getIssuer(offer: CredentialOffer, with dPopConstructor: DPoPConstructorType) async throws -> Issuer {
		try await MainActor.run {
			try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession), dpopConstructor: dPopConstructor)
		}
	}
	
	private func fetchIssuerAndOfferWithLatestMetadata(_ docType: String?, scope: String?, identifier: String?, dpopConstructor: DPoPConstructorType) async throws -> (Issuer?, CredentialOffer?) {
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
		switch issuerMetadata {
			
		case .success(let metaData):
			if let authorizationServer = metaData.authorizationServers?.first {
				let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
				let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
				//				try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
				// Authorize with auth code flow
				let issuer = try await getIssuer(offer: offer, with: dpopConstructor)
				return (issuer, offer)
			}
		case .failure(_):
			throw WalletError(description: "Unable to get issuer metadata")
		}
		return (nil, nil)
	}
	
	private func authorizePARWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer, wia: IssuerDPoPConstructorParam) async throws -> (AuthorizedRequest?, AuthorizeRequestOutcome?) {
		var pushedAuthorizationRequestEndpoint = ""
		if case let .oidc(metaData) = offer.authorizationServerMetadata,
		   let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
		} else if case let .oauth(metaData) = offer.authorizationServerMetadata,
				  let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
		}
		guard !pushedAuthorizationRequestEndpoint.isEmpty else { throw WalletError(description: "pushed Authorization Request Endpoint is nil") }
		logger.info("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		
		let parPlaced = try await issuer.pushAuthorizationCodeRequest(credentialOffer: offer)
		
		if case let .success(request) = parPlaced,
		   case let .par(parRequested) = request {
			OpenId4VCIService.parReqCache = request
			self.parRequested = parRequested
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			
			return (nil, .presentation_request(parRequested.getAuthorizationCodeURL.url))
			
		} else if case let .failure(failure) = parPlaced {
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}
	
	private func handleAuthorizationCodeBothCases(issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
		let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request)
			
			if case let .success(authorized) = authorizedRequest {
				if case let .proofRequired(token,_, _, _, _, _) = authorized {
					let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
					return authorized
				} else if case let .success(authorized) = authorizedRequest,
						  case let .noProofRequired(token,_, _, _, _) = authorized {
					let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
					return authorized
				}
			}
			//            if case let .success(authorized) = authorizedRequest,
			//                case let .noProofRequired(token, _, _, _, _) = authorized {
			//                let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
			//                return authorized
			//            }
			throw WalletError(description: "Failed to get access token")
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}
	
	private func converAuthorizedRequestToParam(authorizedRequest: AuthorizedRequest) -> AuthorizedRequestParams? {
		var authReqParams: AuthorizedRequestParams? = nil
		switch authorizedRequest {
		case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp, let dPopNonce):
			authReqParams = AuthorizedRequestParams(accessToken: accessToken.accessToken, refreshToken: refreshToken?.refreshToken, cNonce: nil, timeStamp: timeStamp, dPopNonce: dPopNonce)
		case .proofRequired(let accessToken, let refreshToken, let cNonce, _, let timeStamp, let dPopNonce):
			authReqParams = AuthorizedRequestParams(accessToken: accessToken.accessToken, refreshToken: refreshToken?.refreshToken, cNonce: cNonce.value, timeStamp: timeStamp, dPopNonce: dPopNonce)
		}
		return authReqParams
	}
}

public struct IssuerDPoPConstructorParam {
	let clientID: String?
	let expirationDuration: TimeInterval?
	let aud: String?
	let jti: String?
	let jwk: JWK
	let privateKey: SecKey
	
	public init(clientID: String?, expirationDuration: TimeInterval?, aud: String?, jti: String?, jwk: JWK, privateKey: SecKey) {
		self.clientID = clientID
		self.expirationDuration = expirationDuration
		self.aud = aud
		self.jti = jti
		self.jwk = jwk
		self.privateKey = privateKey
	}
}

public struct AuthorizedRequestParams: Sendable {
	public let accessToken: String
	public let refreshToken: String?
	public let cNonce: String?
	public let timeStamp: TimeInterval
	public let dPopNonce: Nonce?
	
	public init(accessToken: String, refreshToken: String?, cNonce: String?, timeStamp: TimeInterval, dPopNonce: Nonce?) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
		self.cNonce = cNonce
		self.timeStamp = timeStamp
		self.dPopNonce = dPopNonce
	}
}
