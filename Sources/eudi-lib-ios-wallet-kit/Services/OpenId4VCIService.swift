//
//  File.swift
//
//
//  Created by ffeli on 11/01/2024.
//

import Foundation
import OpenID4VCI
import JOSESwift
import MdocDataModel18013
import AuthenticationServices
import Logging
import CryptoKit
import Security

public class OpenId4VCIService: NSObject, ASWebAuthenticationPresentationContextProviding {
	let credentialIssuerURL: String
	var privateKey: SecKey!
	var publicKey: SecKey!
	var bindingKey: BindingKey!
	let logger: Logger
	let config: WalletOpenId4VCIConfig
	
	init(credentialIssuerURL: String, clientId: String, callbackScheme: String) {
		self.credentialIssuerURL = credentialIssuerURL
		logger = Logger(label: "OpenId4VCI")
		config = .init(clientId: clientId, authFlowRedirectionURI: URL(string: callbackScheme)!)
	}
	
	public func issueDocument(docType: String, format: DataFormat, useSecureEnclave: Bool = false) async throws -> Data {
		privateKey = try KeyController.generateECDHPrivateKey()
		publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		let alg = JWSAlgorithm(.ES256)
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey,additionalParameters: ["alg": alg.name,"use": "sig","kid": UUID().uuidString])
		bindingKey = .jwk(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKey)
		let scope = try Self.findScope(docType: docType, format: format)
		let str = try await issueByScope(scope)
		guard let data = Data(base64Encoded: str) else { throw OpenId4VCIError.dataNotValid }
		return data
	}
		
	func issueByScope(_ scope: String) async throws -> String {
		let credentialIdentifier = try CredentialIdentifier(value: scope)
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		
		let issuerMetadata = await CredentialIssuerMetadataResolver().resolve(source: .credentialIssuer( credentialIssuerIdentifier))
		switch issuerMetadata {
		case .success(let metaData):
			if let authorizationServer = metaData?.authorizationServers.first, let metaData {
				let authServerMetadata = await AuthorizationServerMetadataResolver().resolve(url: authorizationServer)
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier,	credentialIssuerMetadata: metaData,
												credentials: [.scope(.init(scope)),	.scope(.init(Constants.OPENID_SCOPE))],	authorizationServerMetadata: try authServerMetadata.get())
				// return "todo" // try await issueOfferedCredentialNoProof(offer: offer, credentialIdentifier: credentialIdentifier	)
				let issuer = try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config)				
				// Authorize with auth code flow
				let authorized = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
				switch authorized {
				case .noProofRequired:
					return try await noProofRequiredSubmissionUseCase(issuer: issuer, noProofRequiredState: authorized, credentialIdentifier: credentialIdentifier)
				case .proofRequired:
					return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, credentialIdentifier: credentialIdentifier)
				}
				
			} else {
				throw ValidationError.error(reason: "Invalid authorization server")
			}
		case .failure:
			throw ValidationError.error(reason: "Invalid issuer metadata")
		}
	}
	
	static func findScope(docType: String, format: DataFormat) throws -> String {
		switch (docType, format) {
		case (EuPidModel.euPidDocType, .cbor):
			return "eu.europa.ec.eudiw.pid_mso_mdoc"
		case (EuPidModel.euPidDocType, .sjwt):
			return "eu.europa.ec.eudiw.pid_vc_sd_jwt"
		default:
			throw WalletError(key: "docType_or_format_not_supported")
		}
	}
	
	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizedRequest {
		var pushedAuthorizationRequestEndpoint = ""
		if case let .oidc(metaData) = offer.authorizationServerMetadata {
			pushedAuthorizationRequestEndpoint = metaData.pushedAuthorizationRequestEndpoint
		} else if case let .oauth(metaData) = offer.authorizationServerMetadata {
			pushedAuthorizationRequestEndpoint = metaData.pushedAuthorizationRequestEndpoint
		}
		logger.info("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		let parPlaced = await issuer.pushAuthorizationCodeRequest(credentials: offer.credentials)
		
		if case let .success(request) = parPlaced, case let .par(parRequested) = request {
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			let authorizationCode = try await loginUserAndGetAuthCode(
				getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url) ?? { throw  ValidationError.error(reason: "Could not retrieve authorization code") }()
			logger.info("--> [AUTHORIZATION] Authorization code retrieved: \(authorizationCode)")
			let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
			
			switch unAuthorized {
			case .success(let request):
				let authorizedRequest = await issuer.requestAccessToken(authorizationCode: request)
				if case let .success(authorized) = authorizedRequest, case let .noProofRequired(token) = authorized {
					logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(token.accessToken)")
					return authorized
				}
			case .failure(let error):
				throw  ValidationError.error(reason: error.localizedDescription)
			}
		}
		throw  ValidationError.error(reason: "Failed to get push authorization code request")
	}
	
	private func noProofRequiredSubmissionUseCase(issuer: Issuer, noProofRequiredState: AuthorizedRequest, credentialIdentifier: CredentialIdentifier) async throws -> String {
		switch noProofRequiredState {
		case .noProofRequired:
			let requestOutcome = try await issuer.requestSingle(noProofRequest: noProofRequiredState, credentialIdentifier: credentialIdentifier, responseEncryptionSpecProvider: { Issuer.createResponseEncryptionSpec($0) })
			switch requestOutcome {
			case .success(let request):
				switch request {
				case .success(let response):
					if let result = response.credentialResponses.first {
						switch result {
						case .deferred(let transactionId):
							return try await deferredCredentialUseCase(issuer: issuer, authorized: noProofRequiredState, transactionId: transactionId)
						case .issued(_, let credential):
							return credential
						}
					} else {
						throw ValidationError.error(reason: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
					return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), credentialIdentifier: credentialIdentifier
					)
				case .failed(error: let error):
					throw ValidationError.error(reason: error.localizedDescription)
				}
			case .failure(let error):
				throw ValidationError.error(reason: error.localizedDescription)
			}
		default: throw ValidationError.error(reason: "Illegal noProofRequiredState case")
		}
	}
	
	private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, credentialIdentifier: CredentialIdentifier?) async throws -> String {
		let requestOutcome = try await issuer.requestSingle(proofRequest: authorized, bindingKey: bindingKey, credentialIdentifier: credentialIdentifier, responseEncryptionSpecProvider:  { Issuer.createResponseEncryptionSpec($0) })
		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId):
						return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: transactionId)
					case .issued(_, let credential):
						return credential
					}
				} else {
					throw ValidationError.error(reason: "No credential response results available")
				}
			case .invalidProof:
				throw ValidationError.error(reason: "Although providing a proof with c_nonce the proof is still invalid")
			case .failed(let error):
				throw ValidationError.error(reason: error.localizedDescription)
			}
		case .failure(let error): throw ValidationError.error(reason: error.localizedDescription)
		}
	}
	
	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId) async throws -> String {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(_, let credential):
				return credential
			case .issuancePending(let transactionId):
				throw ValidationError.error(reason: "Credential not ready yet. Try after \(transactionId.interval ?? 0)")
			case .errored(_, let errorDescription):
				throw ValidationError.error(reason: "\(errorDescription ?? "Something went wrong with your deferred request response")")
			}
		case .failure(let error):
			throw ValidationError.error(reason: error.localizedDescription)
		}
	}
	
	@MainActor
	private func loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL) async throws -> String? {
		return try await withCheckedThrowingContinuation { c in // eudi-openid4ci // config.authFlowRedirectionURI.absoluteString
			let authenticationSession = ASWebAuthenticationSession(url: getAuthorizationCodeUrl, callbackURLScheme: "eudi-openid4ci") { optionalUrl, optionalError in
				// authorization server stores the code_challenge and redirects the user back to the application with an authorization code, which is good for one use
				// c.resume(returning: "7bd3854e-6b0f-42b7-8b2b-083c48fcb4a0.da9ca3b1-0b9c-4674-8051-52149c1b0717.946f2917-2177-4a87-8e4f-463c6972819a"); return
				guard optionalError == nil else { c.resume(throwing: OpenId4VCIError.authRequestFailed(optionalError!)); return }
				guard let url = optionalUrl else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl); return }
				guard let code = url.getQueryStringParameter("code") else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoCode); return }
				// 4. sends this code and the code_verifier (created in step 2) to the authorization server (token endpoint)
				//self.getAccessToken(authCode: code, codeVerifier: code_verifier, parameters: parameters, completion: completion)
				c.resume(returning: code)
			}
			authenticationSession.presentationContextProvider = self
			authenticationSession.start()
		}
	}

	public func presentationAnchor(for session: ASWebAuthenticationSession)
	-> ASPresentationAnchor {
		let window = UIApplication.shared.windows.first { $0.isKeyWindow }
		return window ?? ASPresentationAnchor()
	}
}

fileprivate extension URL {
	func getQueryStringParameter(_ parameter: String) -> String? {
		guard let url = URLComponents(string: self.absoluteString) else { return nil }
		return url.queryItems?.first(where: { $0.name == parameter })?.value
	}
}

extension SecureEnclave.P256.Signing.PrivateKey {

	func toSecKey() throws -> SecKey {
		var errorQ: Unmanaged<CFError>?
		guard let sf = SecKeyCreateWithData(self.dataRepresentation as NSData, [
			kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeyClass: kSecAttrKeyClassPrivate,
			kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
		] as NSDictionary, &errorQ) else { throw errorQ!.takeRetainedValue() as Error }
		return sf
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

public struct OAuth2PKCEParameters {
	public var authorizeUrl: String
	public var tokenUrl: String
	public var clientId: String
	public var redirectUri: String
	public var callbackURLScheme: String
}


public struct AccessTokenResponse: Codable {
	public var access_token: String
	public var expires_in: Int
}


