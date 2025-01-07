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
    
    func issuePAR(docType: String?, scope: String?, identifier: String?, wia: String, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
        guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope must be provided") }
        logger.log(level: .info, "Issuing document with docType or scope or identifier: \(docTypeOrScopeOrIdentifier)")
        let res = try await issueByPARType(docType, scope: scope, identifier: nil, promptMessage: promptMessage)
        return res
    }
    
    func issueByPARType(_ docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
            let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
            let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
            switch issuerMetadata {
            case .success(let metaData):
                if let authorizationServer = metaData.authorizationServers?.first {
                    let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
                    let configuration = try getCredentialIdentifier(credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
                    
                    let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.identifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
                    
                    // Authorize with auth code flow
                    let issuer = try getIssuer(offer: offer)
                    
                    let authorizedOutcome = (try await authorizePARWithAuthCodeUseCase(issuer: issuer, offer: offer)).1
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
    
    func getCredentials(dpopNonce: String, code: String, scope: String?, claimSet: ClaimSet? = nil, identifier: String?, docType: String?) async throws -> (IssuanceOutcome?, DocDataFormat?) {
        do {
            if let key = OpenId4VCIService.metadataCache.keys.first,
                let credential = OpenId4VCIService.metadataCache[key],
                let unauthorizedRequest = OpenId4VCIService.parReqCache {
                if let issuer = try getIssuerWithDpopConstructor(offer: credential) {
                    let unAuthorized = try await handleAuthorizationCode(nonce: Nonce(value: dpopNonce), issuer: issuer, request: unauthorizedRequest, authorizationCode: code)
                    
                    if credential.credentialConfigurationIdentifiers.first != nil {
                        do {
                            
                            let configuration = try await getCredentialIdentifier(credentialsSupported: issuer.issuerMetadata.credentialsSupported, identifier: nil, docType: docType, scope: scope)
                            
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
    
    func handleAuthorizationCode(nonce: Nonce, issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
        let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
        switch unAuthorized {
        case .success(let request):
            let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request, nonce: nonce)
            
            if case let .success(authorized) = authorizedRequest,
               case let .proofRequired(token,_, _, _, _, _) = authorized {
                let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
                return authorized
            }
//                case let .noProofRequired(token, _, _, _, _) = authorized {
//                let at = token.accessToken;    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(at)")
//                return authorized
//            }
            throw WalletError(description: "Failed to get access token")
        case .failure(let error):
            throw WalletError(description: error.localizedDescription)
        }
    }
    
    public func getIssuerWithDpopConstructor(offer: CredentialOffer) throws -> Issuer? {
            let privateKey = try? KeyController.generateECDHPrivateKey()
            if let privateKey,
               let publicKey = try? KeyController.generateECDHPublicKey(from: privateKey) {
                
                let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
                let dpopConstructor = DPoPConstructor(algorithm: alg, jwk: publicKeyJWK, privateKey: .secKey(privateKey))
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
}
