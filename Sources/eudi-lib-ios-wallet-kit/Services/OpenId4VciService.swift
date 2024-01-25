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

public class OpenId4VCIService: NSObject, ASWebAuthenticationPresentationContextProviding {
	let credentialIssuerURL: String
	var privateKey: SecKey!
	var publicKey: SecKey!
	var seKey: SecureEnclave.P256.Signing.PrivateKey!
	var bindingKey: BindingKey!
	var usedSecureEnclave: Bool!
	let logger: Logger
	let config: WalletOpenId4VCIConfig
	let alg = JWSAlgorithm(.ES256)

	init(credentialIssuerURL: String, clientId: String, callbackScheme: String) {
		self.credentialIssuerURL = credentialIssuerURL
		logger = Logger(label: "OpenId4VCI")
		config = .init(clientId: clientId, authFlowRedirectionURI: URL(string: callbackScheme)!)
	}
	
	/// Issue a document with the given `docType` using OpenId4Vci protocol
	/// - Parameters:
	///   - docType: the docType of the document to be issued
	///   - format: format of the exchanged data
	///   - useSecureEnclave: use secure enclave to protect the private key (to be implemented)
	/// - Returns: The data of the document
	public func issueDocument(docType: String, format: DataFormat = .cbor, useSecureEnclave: Bool = true) async throws -> Data {
		usedSecureEnclave = !useSecureEnclave || !SecureEnclave.isAvailable
		if usedSecureEnclave { seKey = try SecureEnclave.P256.Signing.PrivateKey() }
		privateKey = if !usedSecureEnclave { try KeyController.generateECDHPrivateKey() } else { try seKey.toSecKey() }
		publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey,additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
		bindingKey = .jwk(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKey)
		let str = try await issueByDocType(docType, format: format)
		guard let data = Data(base64URLEncoded: str) else { throw OpenId4VCIError.dataNotValid }
		return data
	}
		
	func issueByDocType(_ docType: String, format: DataFormat) async throws -> String {
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
		let issuerMetadata = await CredentialIssuerMetadataResolver().resolve(source: .credentialIssuer( credentialIssuerIdentifier))
		switch issuerMetadata {
		case .success(let metaData):
			if let authorizationServer = metaData?.authorizationServers.first, let metaData {
				let authServerMetadata = await AuthorizationServerMetadataResolver().resolve(url: authorizationServer)
				let (credentialIdentifier, _, _) = try getCredentialIdentifier(credentialsSupported: metaData.credentialsSupported, docType: docType, format: format)
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentials: [.init(value: credentialIdentifier.value), .init(value: "openid")], authorizationServerMetadata: try authServerMetadata.get())
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
				throw WalletError(description: "Invalid authorization server")
			}
		case .failure:
			throw WalletError(description: "Invalid issuer metadata")
		}
	}
	
	func getCredentialIdentifier(credentialsSupported: [CredentialIdentifier: SupportedCredential], docType: String, format: DataFormat) throws -> (CredentialIdentifier, SupportedCredential, String) {
		switch format {
		case .cbor:
			guard let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType { true } else { false } }), let scope = credential.value.getScope() else {
				logger.error("No credential for \(docType). Currently supported credentials: \(credentialsSupported.values)")
				throw WalletError(description: "Issuer does not support \(docType)")
			}
			if credential.value.cryptographicSuitesSupported?.contains(alg.name) ?? false {
				return (credential.key, credential.value, scope)
			} else {
				logger.error("No supported cryptographic suite for \(docType). Currently supported cryptographic suites: \(credential.value.cryptographicSuitesSupported?.joined(separator: ",") ?? "")")
				throw WalletError(description: "Not supported cryptography  suite for \(docType)")
			}
		default:
			throw WalletError(description: "Format \(format) not yet supported")
		}
	}
	
	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizedRequest {
		var pushedAuthorizationRequestEndpoint = ""
		if case let .oidc(metaData) = offer.authorizationServerMetadata, let pare = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = pare
		} else if case let .oauth(metaData) = offer.authorizationServerMetadata, let pare = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = pare
		}
		logger.info("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
		let parPlaced = await issuer.pushAuthorizationCodeRequest(credentials: offer.credentials)
		
		if case let .success(request) = parPlaced, case let .par(parRequested) = request {
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			let authorizationCode = try await loginUserAndGetAuthCode(
				getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url) ?? { throw WalletError(description: "Could not retrieve authorization code") }()
			logger.info("--> [AUTHORIZATION] Authorization code retrieved")
			let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
			switch unAuthorized {
			case .success(let request):
				let authorizedRequest = await issuer.requestAccessToken(authorizationCode: request)
				if case let .success(authorized) = authorizedRequest, case .noProofRequired(_) = authorized {
					logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token")
					return authorized
				}
			case .failure(let error):
				throw  WalletError(description: error.localizedDescription)
			}
		}
		throw WalletError(description: "Failed to get push authorization code request")
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
						throw WalletError(description: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
					return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), credentialIdentifier: credentialIdentifier)
				case .failed(error: let error):
					throw WalletError(description: error.localizedDescription)
				}
			case .failure(let error):
				throw WalletError(description: error.localizedDescription)
			}
		default: throw WalletError(description: "Illegal noProofRequiredState case")
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
	
	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId) async throws -> String {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId)
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

extension SecureEnclave.P256.Signing.PrivateKey {

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

extension SupportedCredential {
	var cryptographicSuitesSupported: [String]? {
		switch self {
		case .msoMdoc(let credential):
			return credential.cryptographicSuitesSupported
		case .w3CSignedJwt(let credential):
			return credential.cryptographicSuitesSupported
		case .w3CJsonLdSignedJwt(let credential):
			return credential.cryptographicSuitesSupported
		case .w3CJsonLdDataIntegrity(let credential):
			return credential.cryptographicSuitesSupported
		case .sdJwtVc(let credential):
			return credential.cryptographicSuitesSupported
		default: return nil
		}
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


