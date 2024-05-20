/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Created on 04/10/2023 
*/

import Foundation
import SwiftCBOR
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SiopOpenID4VP
import JOSESwift
import Logging
import X509
/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP – Draft 18 specification
public class OpenId4VpService: PresentationService {
	public var status: TransferStatus = .initialized
	var openid4VPlink: String
	var docs: [DeviceResponse]!
	var iaca: [SecCertificate]!
	var dauthMethod: DeviceAuthMethod
	var devicePrivateKeys: [CoseKeyPrivate]!
	var logger = Logger(label: "OpenId4VpService")
	var presentationDefinition: PresentationDefinition?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var openId4VpVerifierApiUri: String?
	var readerAuthValidated: Bool = false
	var readerCertificateIssuer: String?
	var readerCertificateValidationMessage: String?
	var mdocGeneratedNonce: String!
	var sessionTranscript: [UInt8]!
	public var flow: FlowType

	public init(parameters: [String: Any], qrCode: Data, openId4VpVerifierApiUri: String?) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		guard let (docs, devicePrivateKeys, iaca, dauthMethod) = MdocHelpers.initializeData(parameters: parameters) else {
			throw PresentationSession.makeError(str: "MDOC_DATA_NOT_AVAILABLE")
		}
		self.docs = docs; self.devicePrivateKeys = devicePrivateKeys; self.iaca = iaca; self.dauthMethod = dauthMethod
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
		self.openId4VpVerifierApiUri = openId4VpVerifierApiUri
	}
	
	public func startQrEngagement() async throws -> String? { nil }
	
	///  Receive request from an openid4vp URL
	///
	/// - Returns: The requested items.
	public func receiveRequest() async throws -> [String: Any] {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw PresentationSession.makeError(str: "Invalid link \(openid4VPlink)") }
		siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri))
			switch try await siopOpenId4Vp.authorize(url: openid4VPURI)  {
			case .notSecured(data: _):
				throw PresentationSession.makeError(str: "Not secure request received.")
			case let .jwt(request: resolvedRequestData):
				self.resolvedRequestData = resolvedRequestData
				switch resolvedRequestData {
				case let .vpToken(vp):
					let responseUri = if case .directPostJWT(let uri) = vp.responseMode { uri.absoluteString } else { "" }
					mdocGeneratedNonce = Openid4VpUtils.generateMdocGeneratedNonce()
					let sessionTranscriptBytes = Openid4VpUtils.generateSessionTranscript(clientId: vp.clientId,
						responseUri: responseUri, nonce: vp.nonce, mdocGeneratedNonce: mdocGeneratedNonce)
					logger.info("Session Transcript: \(sessionTranscriptBytes.toHexString()), for clientId: \(vp.clientId), responseUri: \(responseUri), nonce: \(vp.nonce), mdocGeneratedNonce: \(mdocGeneratedNonce!)")
					self.presentationDefinition = vp.presentationDefinition
					let items = try Openid4VpUtils.parsePresentationDefinition(vp.presentationDefinition, logger: logger)
					guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
					var result: [String: Any] = [UserRequestKeys.valid_items_requested.rawValue: items, UserRequestKeys.session_transcript_bytes.rawValue: sessionTranscriptBytes]
					if let readerCertificateIssuer {
						result[UserRequestKeys.reader_auth_validated.rawValue] = readerAuthValidated
						result[UserRequestKeys.reader_certificate_issuer.rawValue] = MdocHelpers.getCN(from: readerCertificateIssuer)
						result[UserRequestKeys.reader_certificate_validation_message.rawValue] = readerCertificateValidationMessage
					}
					return result
				default: throw PresentationSession.makeError(str: "SiopAuthentication request received, not supported yet.")
				}
			}
	}
	
	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws {
		guard let pd = presentationDefinition, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpToken(nil, pd, resolved, onSuccess)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend)")
		guard let (deviceResponse, _, _) = try MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, deviceResponses: docs, selectedItems: itemsToSend, devicePrivateKeys: devicePrivateKeys, dauthMethod: dauthMethod) else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		// Obtain consent
		let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
		try await SendVpToken(vpTokenStr, pd, resolved, onSuccess)
	}
	
	fileprivate func SendVpToken(_ vpTokenStr: String?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?) async throws {
		let consent: ClientConsent = if let vpTokenStr {
			.vpToken(vpToken: .msoMdoc(vpTokenStr, apu: mdocGeneratedNonce.base64urlEncode), presentationSubmission: .init(id: UUID().uuidString, definitionID: pd.id, descriptorMap: pd.inputDescriptors.filter { $0.formatContainer?.formats.contains(where: { $0["designation"].string?.lowercased() == "mso_mdoc" }) ?? false }.map { DescriptorMap(id: $0.id, format: "mso_mdoc", path: "$")} ))
		} else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri))
		let result: DispatchOutcome = try await siopOpenId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
			onSuccess?(url)
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
	}
	
	lazy var chainVerifier: CertificateTrust = { [weak self] certificates in
		let chainVerifier = X509CertificateChainVerifier()
		let verified = try? chainVerifier.verifyCertificateChain(base64Certificates: certificates)
		var result = chainVerifier.isChainTrustResultSuccesful(verified ?? .failure)
		guard let self, let b64cert = certificates.first, let data = Data(base64Encoded: b64cert), let str = String(data: data, encoding: .utf8) else { return result }
		guard let certData = Data(base64Encoded: str.removeCertificateDelimiters()), let cert = SecCertificateCreateWithData(nil, certData as CFData), let x509 = try? X509.Certificate(derEncoded: [UInt8](certData)) else { return result }
		self.readerCertificateIssuer = x509.subject.description
		let (isValid, validationMessages, _) = SecurityHelpers.isMdocCertificateValid(secCert: cert, usage: .mdocAuth, rootCerts: self.iaca ?? [])
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = validationMessages.joined(separator: "\n")
		return result
	}
	
	/// OpenId4VP wallet configuration
	func getWalletConf(verifierApiUrl: String?) -> WalletOpenId4VPConfiguration? {
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
					let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
		var supportedClientIdSchemes: [SupportedClientIdScheme] = [.x509SanDns(trust: chainVerifier), .x509SanDns(trust: chainVerifier)]
		if let verifierApiUrl {
			let verifierMetaData = PreregisteredClient(clientId: "Verifier", jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUrl)/wallet/public-keys.json")!))
			supportedClientIdSchemes += [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])]
	  }
		let res = WalletOpenId4VPConfiguration(subjectSyntaxTypesSupported: [.decentralizedIdentifier, .jwkThumbprint], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: supportedClientIdSchemes, vpFormatsSupported: [])
		return res
	}
	
}

