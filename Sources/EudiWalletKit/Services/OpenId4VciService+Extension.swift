//
//  Untitled.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 20.12.24.
//

import Foundation
@preconcurrency import OpenID4VCI
import MdocDataModel18013
import CryptorECC
import JOSESwift

extension OpenId4VCIService {
    
    func issuePAR(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, wia: WalletInstanceAttestationPAR) async throws -> (IssuanceOutcome, DocDataFormat) {
        guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope must be provided") }
        logger.log(level: .info, "Issuing document with docType or scope or identifier: \(docTypeOrScopeOrIdentifier)")
        let res = try await issueByPARType(docType, scope: scope, identifier: nil, promptMessage: promptMessage, wia: wia)
        return res
    }
    
    func issueByPARType(_ docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, claimSet: ClaimSet? = nil, wia: WalletInstanceAttestationPAR) async throws -> (IssuanceOutcome, DocDataFormat) {
            let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
            let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
            switch issuerMetadata {
            case .success(let metaData):
                if let authorizationServer = metaData.authorizationServers?.first {
                    let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
                    let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
                    
                    let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
                    
                    let dPopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: wia.jwk, privateKey: .secKey(wia.privateKey))
                    // Authorize with auth code flow
                    let issuer = try getIssuer(offer: offer, with: dPopConstructor)
                    
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
    
    func getIssuer(offer: CredentialOffer, with dPopConstructor: DPoPConstructorType) throws -> Issuer {
        try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession))
//        try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession), dpopConstructor: dPopConstructor)
    }
    
    private func authorizePARWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer, wia: WalletInstanceAttestationPAR) async throws -> (AuthorizedRequest?, AuthorizeRequestOutcome?) {
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
//        let jwtSpec = ClientAttestationPoPJWTSpec(duration: wia.expirationDuration, typ: "", issuer: wia.clientID, audience: wia.aud, nonce: nil)
//        
//        let clientAttestation = ClientAttestation(clientAttestationPoPJWTType: jwtSpec, clientAttestationJWT: wia.wia)
//        
//        let parPlaced = try await issuer.pushAuthorizationCodeRequest(credentialOffer: offer, clientAttestation: clientAttestation)
            
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
    
    func getCredentials(dpopNonce: String, code: String, scope: String?, claimSet: ClaimSet? = nil, identifier: String?, docType: String?) async throws -> (IssuanceOutcome?, DocDataFormat?) {
        do {
            try addNonceToUnauthorizedRequest(dpopNonce: dpopNonce)
            if let key = OpenId4VCIService.metadataCache.keys.first,
                let offer = OpenId4VCIService.metadataCache[key],
                let unauthorizedRequest = OpenId4VCIService.parReqCache {
                let privateKey = try? KeyController.generateECDHPrivateKey()
                if let privateKey,
                   let publicKey = try? KeyController.generateECDHPublicKey(from: privateKey) {
                    let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
                    let dpopConstructor = DPoPConstructor(algorithm: alg, jwk: publicKeyJWK, privateKey: .secKey(privateKey))
                    let issuer = try getIssuer(offer: offer, with: dpopConstructor)
                    
                    let unAuthorized = try await handleAuthorizationCode(nonce: Nonce(value: dpopNonce), issuer: issuer, request: unauthorizedRequest, authorizationCode: code)
                 
                    if offer.credentialConfigurationIdentifiers.first != nil {
                        do {
                            let configuration = try  getCredentialIdentifier(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: nil, docType: docType, scope: scope)
//                            let configuration = try await getCredentialIdentifier(credentialsSupported: issuer.issuerMetadata.credentialsSupported, identifier: nil, docType: docType, scope: scope)
//                            
                            try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
                            
                            let issuanceOutcome = try await issueOfferedCredentialInternal(unAuthorized, issuer: issuer, configuration: configuration, claimSet: claimSet)

                            return (issuanceOutcome, DocDataFormat.cbor)
                            
                        } catch {
                            throw WalletError(description: "Invalid issuer metadata")
                        }
                    }
                    
                }
            }
        } catch  {
            throw WalletError(description: "Invalid issuer metadata")
        }
        return (nil, nil)
    }
    
    private func addNonceToUnauthorizedRequest(dpopNonce: String) throws {
        let request: UnauthorizedRequest?
        
        guard let req = OpenId4VCIService.parReqCache else {
            return
        }
        switch req {
        case .par(let parRequested):
            print(parRequested)
            let parReq = try ParRequested(
                credentials: parRequested.credentials,
                getAuthorizationCodeURL: parRequested.getAuthorizationCodeURL,
                pkceVerifier: parRequested.pkceVerifier,
                state: parRequested.state,
                configurationIds: parRequested.configurationIds,
                dpopNonce: Nonce(value: dpopNonce)
            )
            request = .par(parReq)
            
        case .authorizationCode(let authTokenRetreived):
            print(authTokenRetreived)
            let authTokenRetreived = try AuthorizationCodeRetrieved(
                credentials: authTokenRetreived.credentials,
                authorizationCode: authTokenRetreived.authorizationCode,
                pkceVerifier: authTokenRetreived.pkceVerifier,
                configurationIds: authTokenRetreived.configurationIds,
                dpopNonce: Nonce(value: dpopNonce)
            )
            request = .authorizationCode(authTokenRetreived)
        }
        OpenId4VCIService.parReqCache = request
    }
    
    func handleAuthorizationCode(nonce: Nonce, issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
        let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
        switch unAuthorized {
        case .success(let request):
//            let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request, nonce: nonce)
            let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request)
            
            if case let .success(authorized) = authorizedRequest {
               if case let .proofRequired(token,_, _, _, _, nonce) = authorized {
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
}

public struct WalletInstanceAttestationPAR {
    let wia: String
    let clientID: String
    let expirationDuration: TimeInterval
    let aud: String
    let jti: String
    let jwk: JWK
    let privateKey: SecKey
    
    public init(wia: String, clientID: String, expirationDuration: TimeInterval, aud: String, jti: String, jwk: JWK, privateKey: SecKey) {
        self.wia = wia
        self.clientID = clientID
        self.expirationDuration = expirationDuration
        self.aud = aud
        self.jti = jti
        self.jwk = jwk
        self.privateKey = privateKey
    }
}
