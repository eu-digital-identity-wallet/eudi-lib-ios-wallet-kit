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
import WalletStorage
@preconcurrency import SiopOpenID4VP
import eudi_lib_sdjwt_swift
import JOSESwift
import Logging
import X509
/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP specification
public final class OpenId4VpService: @unchecked Sendable, PresentationService {
	public var status: TransferStatus = .initialized
	var openid4VPlink: String
	// map of document id to data
	var formats: [String: String]!
	var docs: [String: Data]!
	var docsCbor: [String: IssuerSigned]!
	var docsSdJwt: [String: SignedSDJWT]!
	var iaca: [SecCertificate]!
	var format: DocDataFormat!
	var dauthMethod: DeviceAuthMethod
	var devicePrivateKeys: [String: CoseKeyPrivate]!
	var logger = Logger(label: "OpenId4VpService")
	var presentationDefinition: PresentationDefinition?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var openId4VpVerifierApiUri: String?
	var openId4VpVerifierLegalName: String?
	var readerAuthValidated: Bool = false
	var readerCertificateIssuer: String?
	var readerCertificateValidationMessage: String?
	var mdocGeneratedNonce: String!
	var sessionTranscript: SessionTranscript!
	var eReaderPub: CoseKey?
	var urlSession: URLSession
	var unlockData: [String: Data]!
	public var flow: FlowType

	public init(parameters: InitializeTransferData, qrCode: Data, openId4VpVerifierApiUri: String?, openId4VpVerifierLegalName: String?, urlSession: URLSession) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		let objs = parameters.toInitializeTransferInfo()
		formats = objs.dataFormats; docs = objs.documentObjects; devicePrivateKeys = objs.privateKeyObjects; iaca = objs.iaca; dauthMethod = objs.deviceAuthMethod
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
		self.openId4VpVerifierApiUri = openId4VpVerifierApiUri
		self.openId4VpVerifierLegalName = openId4VpVerifierLegalName
		self.urlSession = urlSession
	}
	
	public func startQrEngagement(secureAreaName: String?, crv: CoseEcCurve) async throws -> String {
		if unlockData == nil {
			unlockData = [String: Data]()
			for (id, key) in devicePrivateKeys {
				let ud = try await key.secureArea.unlockKey(id: id)
				if let ud { unlockData[id] = ud }
			}
		}
		return ""
	}
	
	///  Receive request from an openid4vp URL
	///
	/// - Returns: The requested items.
	public func receiveRequest() async throws -> UserRequestInfo {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw PresentationSession.makeError(str: "Invalid link \(openid4VPlink)") }
		siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri, verifierLegalName: openId4VpVerifierLegalName))
			switch try await siopOpenId4Vp.authorize(url: openid4VPURI)  {
			case .notSecured(data: _):
				throw PresentationSession.makeError(str: "Not secure request received.")
			case let .jwt(request: resolvedRequestData):
				self.resolvedRequestData = resolvedRequestData
				switch resolvedRequestData {
				case let .vpToken(vp):
					if let key = vp.clientMetaData?.jwkSet?.keys.first(where: { $0.use == "enc"}), let x = key.x, let xd = Data(base64URLEncoded: x), let y = key.y, let yd = Data(base64URLEncoded: y), let crv = key.crv, let crvType = MdocDataModel18013.CoseEcCurve(crvName: crv)  {
						logger.info("Found jwks public key with curve \(crv)")
						eReaderPub = CoseKey(x: [UInt8](xd), y: [UInt8](yd), crv: crvType)
					}
					let responseUri = if case .directPostJWT(let uri) = vp.responseMode { uri.absoluteString } else { "" }
					mdocGeneratedNonce = Openid4VpUtils.generateMdocGeneratedNonce()
					sessionTranscript = Openid4VpUtils.generateSessionTranscript(clientId: vp.client.id,
						responseUri: responseUri, nonce: vp.nonce, mdocGeneratedNonce: mdocGeneratedNonce)
					logger.info("Session Transcript: \(sessionTranscript.encode().toHexString()), for clientId: \(vp.client.id), responseUri: \(responseUri), nonce: \(vp.nonce), mdocGeneratedNonce: \(mdocGeneratedNonce!)")
					self.presentationDefinition = vp.presentationDefinition
					let (items, fmt) = try Openid4VpUtils.parsePresentationDefinition(vp.presentationDefinition, logger: logger)
					self.format = fmt
					guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
					var result = UserRequestInfo(validItemsRequested: items)
					logger.info("Verifer requested items: \(items.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
					if let ln = resolvedRequestData.legalName { result.readerLegalName = ln }
					if let readerCertificateIssuer {
						result.readerAuthValidated = readerAuthValidated
						result.readerCertificateIssuer = MdocHelpers.getCN(from: readerCertificateIssuer)
						result.readerCertificateValidationMessage = readerCertificateValidationMessage
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
		logger.info("Openid4vp request items: \(itemsToSend.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
		if unlockData == nil { _ = try await startQrEngagement(secureAreaName: nil, crv: .P256) }
		if format == .cbor {
			docsCbor = docs.filter { k,v in Self.filterFormat(formats[k]!, fmt: .cbor)} .mapValues { IssuerSigned(data: $0.bytes) }.compactMapValues { $0 }
			guard let (deviceResponse, _, _) = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, issuerSigned: docsCbor, selectedItems: itemsToSend, eReaderKey: eReaderPub, devicePrivateKeys: devicePrivateKeys, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: unlockData) else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
			// Obtain consent
			let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
			try await SendVpToken([VpToken.VerifiablePresentation.msoMdoc(vpTokenStr)], pd, resolved, onSuccess)
		} else {
			let parser = CompactParser()
			let docStrings = docs.filter { k,v in Self.filterFormat(formats[k]!, fmt: .sdjwt)}.compactMapValues { String(data: $0, encoding: .utf8) } 
			docsSdJwt = docStrings.compactMapValues { try? parser.getSignedSdJwt(serialisedString: $0) }
			// support first document
			for (docId, nsItems) in itemsToSend {
				let docSigned = docsSdJwt[docId]; let dpk = devicePrivateKeys[docId]
				guard let docSigned, let dpk, let items = nsItems.first?.value.map(\.elementIdentifier) else { continue }
				let unlockData = try await dpk.secureArea.unlockKey(id: docId)
				let keyInfo = try await dpk.secureArea.getKeyInfo(id: docId);	let dsa = keyInfo.publicKey.crv.defaultSigningAlgorithm
				let signer = try SecureAreaSigner(secureArea: dpk.secureArea, id: docId, ecAlgorithm: dsa, unlockData: unlockData)
				let signAlg = try SecureAreaSigner.getSigningAlgorithm(dsa)
				guard let presented = try await Openid4VpUtils.getSdJwtPresentation(docSigned, signer: signer, signAlg: signAlg, requestItems: items, nonce: mdocGeneratedNonce, aud: openid4VPlink) else { continue }
				try await SendVpToken([VpToken.VerifiablePresentation.generic(presented.serialisation)] , pd, resolved, onSuccess)
				break
			}
		}
	}
	/// Filter document accordind to the raw format value
	static func filterFormat(_ s: String, fmt: DocDataFormat) -> Bool { s == fmt.rawValue }

	fileprivate func SendVpToken(_ vpTokens: [VpToken.VerifiablePresentation]?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?) async throws {
		let consent: ClientConsent = if let vpTokens {
			.vpToken(vpToken: .init(apu: mdocGeneratedNonce.base64urlEncode, verifiablePresentations: vpTokens), presentationSubmission: .init(id: UUID().uuidString, definitionID: pd.id, descriptorMap: pd.inputDescriptors.map {DescriptorMap(id: $0.id, format: $0.formatContainer?.formats.first?["designation"].string ?? "", path: "$")}))
		} else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri, verifierLegalName: openId4VpVerifierLegalName))
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
		guard let self else { return false }
		let chainVerifier = eudi_lib_sdjwt_swift.X509CertificateChainVerifier()
		let verified = try? chainVerifier.verifyCertificateChain(base64Certificates: certificates)
		var result = chainVerifier.isChainTrustResultSuccesful(verified ?? .failure)
		let b64certs = certificates; let data = b64certs.compactMap { Data(base64Encoded: $0) }
		let certs = data.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		guard certs.count > 0, certs.count == b64certs.count else { return result }
		guard let x509 = try? X509.Certificate(derEncoded: [UInt8](data.first!)) else { return result }
		self.readerCertificateIssuer = x509.subject.description
		let (isValid, validationMessages, _) = SecurityHelpers.isMdocX5cValid(secCerts: certs, usage: .mdocReaderAuth, rootCerts: self.iaca ?? [])
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = validationMessages.joined(separator: "\n")
		return result
	}
	
	/// OpenId4VP wallet configuration
	func getWalletConf(verifierApiUrl: String?, verifierLegalName: String?) -> SiopOpenId4VPConfiguration? {
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
					let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
		var supportedClientIdSchemes: [SupportedClientIdScheme] = [.x509SanUri(trust: chainVerifier), .x509SanDns(trust: chainVerifier)]
		if let verifierApiUrl, let verifierLegalName {
			let verifierMetaData = PreregisteredClient(clientId: "Verifier", legalName: verifierLegalName, jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUrl)/wallet/public-keys.json")!))
			supportedClientIdSchemes += [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])]
	  }
		let res = SiopOpenId4VPConfiguration(subjectSyntaxTypesSupported: [.decentralizedIdentifier, .jwkThumbprint], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: supportedClientIdSchemes, vpFormatsSupported: [], session: urlSession)
		return res
	}
	
}

