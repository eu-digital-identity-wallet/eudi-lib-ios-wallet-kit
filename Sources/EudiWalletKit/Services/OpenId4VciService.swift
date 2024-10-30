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
	var bindingKey: BindingKey!
	var usedSecureEnclave: Bool!
	let logger: Logger
	let config: OpenId4VCIConfig
	let alg = JWSAlgorithm(.ES256)
	static var metadataCache = [String: CredentialOffer]()
    //TODO: remove following, use it in better way
    static var parReqCache: UnauthorizedRequest?
	var urlSession: URLSession
	var parRequested: ParRequested?
    var offer: CredentialOffer? = nil
    
	init(issueRequest: IssueRequest, credentialIssuerURL: String, config: OpenId4VCIConfig, urlSession: URLSession) {
		self.issueReq = issueRequest
		self.credentialIssuerURL = credentialIssuerURL
		self.urlSession = urlSession
		logger = Logger(label: "OpenId4VCI")
		self.config = config
	}
	
	func initSecurityKeys(_ useSecureEnclave: Bool) throws {
		var privateKey: SecKey
		var publicKey: SecKey
		usedSecureEnclave = useSecureEnclave && SecureEnclave.isAvailable
		if !usedSecureEnclave {
			let key = try P256.KeyAgreement.PrivateKey(x963Representation: issueReq.keyData)
			privateKey = try key.toSecKey()
		} else {
			let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: issueReq.keyData)
			privateKey = try seKey.toSecKey()
		}
		publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
		bindingKey = .jwk(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKey, issuer: config.clientId)
	}
    
    /// Issue a document with the given `docType` using OpenId4Vci protocol
    /// - Parameters:
    ///   - docType: the docType of the document to be issued
    ///   - format: format of the exchanged data
    ///   - useSecureEnclave: use secure enclave to protect the private key
    /// - Returns: The data of the document
    func issuePAR(docType: String, format: DataFormat, promptMessage: String? = nil, useSecureEnclave: Bool = true) async throws -> IssuanceOutcome {
        try initSecurityKeys(useSecureEnclave)
        let res = try await issueByPARType(docType, format: format, promptMessage: promptMessage)
        return res
    }
    
    func issueByPARType(_ docType: String, format: DataFormat, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
        let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
        let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
        switch issuerMetadata {
        case .success(let metaData):
            if let authorizationServer = metaData.authorizationServers?.first {
                let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
                let (credentialConfigurationIdentifier, _, _) = try getCredentialIdentifier(credentialsSupported: metaData.credentialsSupported, docType: docType, format: format)
                let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [credentialConfigurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
                // Authorize with auth code flow
                let issuer = try getIssuer(offer: offer)
                
              
                let authorizedOutcome = (try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer)).1
                if case .presentation_request(let url) = authorizedOutcome, let parRequested {
                    logger.info("Dynamic issuance request with url: (url)")
                    let uuid = UUID().uuidString
                    Self.metadataCache[uuid] = offer
                    return    .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), identifier: credentialConfigurationIdentifier, displayName: "", metadataKey: uuid, pckeCodeVerifier: parRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: parRequested.pkceVerifier.codeVerifierMethod ))
                }
                guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
                return try await issueOfferedCredentialInternalIssuanceOutcome(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: "", claimSet: claimSet)
            } else {
                throw WalletError(description: "Invalid authorization server")
            }
        case .failure:
            throw WalletError(description: "Invalid issuer metadata")
        }
    }
    
    private func issueOfferedCredentialInternalIssuanceOutcome(_ authorized: AuthorizedRequest, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, displayName: String?, claimSet: ClaimSet?) async throws -> IssuanceOutcome {
        
        switch authorized {
        case .noProofRequired:
            let result = try await noProofRequiredSubmissionUseCaseIssuanceOutcome(issuer: issuer, noProofRequiredState: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName, claimSet: claimSet)
            return result
        case .proofRequired:
            return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName, claimSet: claimSet)
        }
    }
    
    private func noProofRequiredSubmissionUseCaseIssuanceOutcome(issuer: Issuer, noProofRequiredState: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, displayName: String?, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
            switch noProofRequiredState {
            case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp):
                let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: credentialConfigurationIdentifier,    claimSet: claimSet)
                let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
                let requestOutcome = try await issuer.requestSingle(noProofRequest: noProofRequiredState, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
                switch requestOutcome {
                case .success(let request):
                    switch request {
                    case .success(let response):
                        if let result = response.credentialResponses.first {
                            switch result {
                            case .deferred(let transactionId):
                                let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, displayName: displayName ?? "", timeStamp: timeStamp)
                                return .deferred(deferredModel)
                            case .issued(_, let credential, _):
                                guard let data = Data(base64URLEncoded: credential) else { throw WalletError(description: "Invalid credential")    }
                                return .issued(data, displayName)
                            }
                        } else {
                            throw WalletError(description: "No credential response results available")
                        }
                    case .invalidProof(let cNonce, _):
                        return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName)
                    case .failed(error: let error):
                        throw WalletError(description: error.localizedDescription)
                    }
                case .failure(let error):
                    throw WalletError(description: error.localizedDescription)
                }
            default: throw WalletError(description: "Illegal noProofRequiredState case")
            }
        }
    
    private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier?, displayName: String?, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
            guard let credentialConfigurationIdentifier else { throw WalletError(description: "Credential configuration identifier not found") }
            
        guard case .proofRequired(let accessToken, let refreshToken, let cNonce, let credentialIdentifiers, let timeStamp, let dpopNonce) = authorized else {
            throw WalletError(description: "Unexpected AuthorizedRequest case")
        }

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
                            let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, displayName: displayName ?? "", timeStamp: timeStamp)
                            return .deferred(deferredModel)
                        case .issued(_, let credential, _):
                            guard let data = Data(base64URLEncoded: credential) else { throw WalletError(description: "Invalid credential")    }
                            return .issued(data, displayName)
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
	
	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(uriOffer: String, format: DataFormat = .cbor) async throws -> OfferedIssuanceModel {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher(session: urlSession), credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession))).resolve(source: try .init(urlString: uriOffer))
		switch result {
		case .success(let offer):
			let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
			Self.metadataCache[uriOffer] = offer
			let credentialInfo = try getCredentialIdentifiers(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, format: format)
			return OfferedIssuanceModel(issuerName: offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
		case .failure(let error):
			throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}
	
    func getIssuer(offer: CredentialOffer, dpopConstructor: DPoPConstructor? = nil) throws -> Issuer {
        try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession), dpopConstructor: dpopConstructor)
	}
    public func getIssuerWithDpopConstructor(offer: CredentialOffer) throws -> Issuer? {
        let privateKey = try? KeyController.generateECDHPrivateKey()
        if let privateKey,
           let publicKey = try? KeyController.generateECDHPublicKey(from: privateKey) {
            let publicKeyJWK = try ECPublicKey(publicKey: publicKey,additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
            let dpopConstructor = DPoPConstructor(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKey)
            return try Issuer(
                authorizationServerMetadata: offer.authorizationServerMetadata,
                issuerMetadata: offer.credentialIssuerMetadata,
                config: config,
                parPoster: Poster(session: urlSession),
                tokenPoster: Poster(session: urlSession),
                requesterPoster: Poster(session: urlSession),
                deferredRequesterPoster: Poster(session: urlSession),
                notificationPoster: Poster(session: urlSession),
                dpopConstructor: dpopConstructor
            )
        }
        return nil
    }
	
	func getIssuerForDeferred(data: DeferredIssuanceModel) throws -> Issuer {
		try Issuer.createDeferredIssuer(deferredCredentialEndpoint: data.deferredCredentialEndpoint, deferredRequesterPoster: Poster(session: urlSession), config: config)
	}
	
	func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String?, format: DataFormat, useSecureEnclave: Bool = true, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> [Data] {
        guard format == .cbor else { throw fatalError("jwt format not implemented") }
        try initSecurityKeys(useSecureEnclave)
        guard let offer = Self.metadataCache[offerUri] else { throw WalletError(description: "offerUri not resolved. resolveOfferDocTypes must be called first")}
        let credentialInfo = docTypes.compactMap { try? getCredentialIdentifier(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, docType: $0.docType, format: format)
        }
        let code: Grants.PreAuthorizedCode? = switch offer.grants {    case .preAuthorizedCode(let preAuthorizedCode):    preAuthorizedCode; case .both(_, let preAuthorizedCode):    preAuthorizedCode; case .authorizationCode(_), .none: nil    }
        let txCodeSpec: TxCode? = code?.txCode
        let preAuthorizedCode: String? = code?.preAuthorizedCode
        let issuer = try getIssuer(offer: offer)
        if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil { throw WalletError(description: "A transaction code is required for this offer") }
        
        let credentialData = [Data]()
        
        if let authorized = if let preAuthorizedCode,
                                let txCodeValue,
                                let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) {
            try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, clientId: config.clientId, transactionCode: txCodeValue).get()
        } else {
            try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer).0
        } {
            let credentialData = await credentialInfo.asyncCompactMap { credentialInfoMap in
                do {
                    logger.info("Starting issuing with identifer \(credentialInfoMap.identifier.value) and scope \(credentialInfoMap.scope)")
                    let str = try await issueOfferedCredentialWithProof(authorized, offer: offer, issuer: issuer, credentialConfigurationIdentifier: credentialInfoMap.identifier, claimSet: claimSet)
                    logger.info("Credential str:\n\(str)")
                    return Data(base64URLEncoded: str)
                    
                } catch {
                    logger.error("Failed to issue document with scope \(credentialInfoMap.scope)")
                    logger.info("Exception: \(error)")
                    return nil
                }
            }
            Self.metadataCache.removeValue(forKey: offerUri)
            return credentialData
        }
        return credentialData
	}
    
    private func issueOfferedCredentialWithProof(_ authorized: AuthorizedRequest, offer: CredentialOffer, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet? = nil) async throws -> String {
        let issuerMetadata = offer.credentialIssuerMetadata
        guard issuerMetadata.credentialsSupported.keys.contains(where: { $0.value == credentialConfigurationIdentifier.value }) else {
            throw WalletError(description: "Cannot find credential identifier \(credentialConfigurationIdentifier.value) in offer")
        }
        return try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: nil, claimSet: claimSet).0
        
    }
	
	private func issueOfferedCredentialInternal(_ authorized: AuthorizedRequest, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, displayName: String?, claimSet: ClaimSet?) async throws -> (String, CNonce?) {
		
		switch authorized {
		case .noProofRequired:
			let result = try await noProofRequiredSubmissionUseCase(issuer: issuer, noProofRequiredState: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName, claimSet: claimSet)
            return (result, nil)
		case .proofRequired:
			return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName, claimSet: claimSet)
		}
	}
	
	private func issueOfferedCredentialInternalValidated(_ authorized: AuthorizedRequest, offer: CredentialOffer, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, displayName: String?, claimSet: ClaimSet? = nil) async throws -> (String, CNonce?) {
		let issuerMetadata = offer.credentialIssuerMetadata
		guard issuerMetadata.credentialsSupported.keys.contains(where: { $0.value == credentialConfigurationIdentifier.value }) else {
			throw WalletError(description: "Cannot find credential identifier \(credentialConfigurationIdentifier.value) in offer")
		}
		return try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName, claimSet: claimSet)
	}
	
	func getCredentialIdentifier(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], docType: String, format: DataFormat) throws -> (identifier: CredentialConfigurationIdentifier, scope: String, displayName: String?) {
		switch format {
		case .cbor:
			guard let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope else {
				logger.error("No credential for docType \(docType). Currently supported credentials: \(credentialsSupported.values)")
				throw WalletError(description: "Issuer does not support doc type\(docType)")
			}
			logger.info("Currently supported cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			//return (identifier: credential.key, scope: scope, docType: docType)
            return (identifier: credential.key, scope: scope, displayName: nil)
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
	
	private func authorizePARWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> (AuthorizedRequest?, AuthorizeRequestOutcome?) {
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
            OpenId4VCIService.parReqCache = request
			self.parRequested = parRequested
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
            
            return (nil, .presentation_request(parRequested.getAuthorizationCodeURL.url))
            
		} else if case let .failure(failure) = parPlaced {
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}
	
    private func handleAuthorizationCode(nonce: String? = "",issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
		let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
		switch unAuthorized {
		case .success(let request):
           
            let authorizedRequest = await issuer.requestAccessToken(dpopNonce: nonce, authorizationCode: request)
            print("Response 2 -------> \(authorizedRequest)")
            
            switch authorizedRequest {
            case .success(let authorized):
                logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token (no proof required) : \(authorized.accessToken)")
                return authorized
            case .failure(let failure):
                throw WalletError(description: "Failed to request access token: \(failure.localizedDescription)")
            }
    	case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}
	
    private func noProofRequiredSubmissionUseCase(issuer: Issuer, noProofRequiredState: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, displayName: String?, claimSet: ClaimSet? = nil) async throws -> String {
		switch noProofRequiredState {
        case .noProofRequired(_, _, _, _):
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
                            return try await deferredCredentialUseCase(issuer: issuer, authorized: noProofRequiredState, transactionId: transactionId)
                        case .issued(_, let credential, _):
                            return credential
						}
					} else {
						throw WalletError(description: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
                    return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), credentialConfigurationIdentifier: credentialConfigurationIdentifier, displayName: displayName).0
				case .failed(error: let error):
					throw WalletError(description: error.localizedDescription)
				}
			case .failure(let error):
				throw WalletError(description: error.localizedDescription)
			}
		default: throw WalletError(description: "Illegal noProofRequiredState case")
		}
	}
    
    private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier?, displayName: String?, claimSet: ClaimSet? = nil) async throws -> (String, CNonce?) {

        guard let credentialConfigurationIdentifier else {
            throw WalletError(description: "Credential configuration identifier not found")
        }
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
                        let deferred = try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: transactionId)
                        return (deferred, response.cNonce)
                    case .issued(_, let credential, _):
                        return (credential, response.cNonce)
                    }
                } else {
                    throw WalletError(description: "No credential response results available")
                }
            case .invalidProof:
                throw WalletError(description: "Although providing a proof with c_nonce the proof is still invalid")
            case .failed(let error):
                throw error
            }
        case .failure(let error):
            throw error
        }
    }
	
	func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> String {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try getIssuerForDeferred(data: model)
		let authorized: AuthorizedRequest = .noProofRequired(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil, timeStamp: model.timeStamp)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId)
	}
	
	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> (String, CNonce?) {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }
		guard let webUrl else { throw WalletError(description: "Web URL not specified") }
		let asWeb = try await loginUserAndGetAuthCode(getAuthorizationCodeUrl: webUrl)
		guard case .code(let authorizationCode) = asWeb else { throw WalletError(description: "Pending issuance not authorized") }
		guard let offer = Self.metadataCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		let issuer = try getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.identifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.requestAccessToken(authorizationCode: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.identifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier))).get()
		let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, credentialConfigurationIdentifier: model.identifier, displayName: model.displayName, claimSet: nil)
		Self.metadataCache.removeValue(forKey: model.metadataKey)
		return res
	}
	
    private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId) async throws -> String {
        logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
        let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId, dpopNonce: authorized.dpopNonce)
        
        switch deferredRequestResponse {
        case .success(let response):
            switch response {
            case .issued(_, let credential):
                return credential
            case .issuancePending(let transactionId):
                throw WalletError(description: "Credential not ready yet. Try after \(transactionId.interval ?? 0)")
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
    
    public func getCredentials(dpopNonce: String, code: String, claimSet: ClaimSet? = nil) async throws -> (Data?) {
        do {
            try initSecurityKeys(usedSecureEnclave ?? true)
            if let key = OpenId4VCIService.metadataCache.keys.first,
                let credential = OpenId4VCIService.metadataCache[key],
                let unauthorizedRequest = OpenId4VCIService.parReqCache {
                if let issuer = try getIssuerWithDpopConstructor(offer: credential) {
                    let authorized = try await handleAuthorizationCode(nonce: dpopNonce, issuer: issuer, request: unauthorizedRequest, authorizationCode: code)
                    
                    if let credentialConfigurationIdentifiers = credential.credentialConfigurationIdentifiers.first {
                        do {
                            let (cbor, _) = try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifiers, displayName: nil, claimSet: claimSet)

                            guard let mdocData = Data(base64URLEncoded:  cbor) else {
                                throw OpenId4VCIError.dataNotValid
                            }
                           return mdocData
                            
                        } catch PostError.useDpopNonce(let newCNonce) {
                            //TODO: As per doc above return error and then following should be called but we are not getting error and it is succeeding with credential, need to evaluate following.
                            var updatedAuthorized = authorized
                            
                            if let cnonce = CNonce(value: newCNonce, expiresInSeconds: nil) {
                                updatedAuthorized.updateCNonce(cnonce)
                                let (_, _) = try await issueOfferedCredentialInternal(updatedAuthorized,
                                                                                     issuer: issuer,
                                                                                          credentialConfigurationIdentifier: credentialConfigurationIdentifiers, displayName: nil,
                                                                                          claimSet: nil)
                            }
                        } catch {
                            throw WalletError(description: "Invalid issuer metadata")
                        }
                    }
                }
            }
        } catch  {
            throw WalletError(description: "Invalid issuer metadata")
        }
        return nil
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


