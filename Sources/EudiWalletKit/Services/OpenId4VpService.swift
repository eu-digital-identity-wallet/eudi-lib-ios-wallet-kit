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
	// map of document-id to data format
	var dataFormats: [String: DocDataFormat]!
	// map of document-id to data
	var docs: [String: Data]!
	var docMetadata: [String: Data?]!
	var docDisplayNames: [String: [String: [String: String]]?]!
	// map of document-id to IssuerSigned
	var docsCbor: [String: IssuerSigned]!
	/// map of document id to document type
	var idsToDocTypes: [String: String]!
	// map of document-id to SignedSDJWT
	var docsSdJwt: [String: SignedSDJWT]!
	// map of document-id to hashing algorithm
	var docsHashingAlgs: [String: String]!
	/// IACA root certificates
	var iaca: [SecCertificate]!
	// map of docType to data format (formats requested)
	var formatsRequested: [String: DocDataFormat]!
	var transactionData: [TransactionData]?
	/// map of docType to inputDescriptor-id
	var inputDescriptorMap: [String: String]!
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
	var certificateChain: [Data]?
	var vpNonce: String!
	var vpClientId: String!
	var mdocGeneratedNonce: String!
	var sessionTranscript: SessionTranscript!
	var eReaderPub: CoseKey?
	var urlSession: URLSession
	var unlockData: [String: Data]!
	public var transactionLog: TransactionLog
	public var flow: FlowType

	public init(parameters: InitializeTransferData, qrCode: Data, openId4VpVerifierApiUri: String?, openId4VpVerifierLegalName: String?, urlSession: URLSession) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		let objs = parameters.toInitializeTransferInfo()
		dataFormats = objs.dataFormats; docs = objs.documentObjects; devicePrivateKeys = objs.privateKeyObjects
		iaca = objs.iaca; dauthMethod = objs.deviceAuthMethod
		docMetadata = parameters.docMetadata
		idsToDocTypes = objs.idsToDocTypes
		docDisplayNames = objs.docDisplayNames
		docsHashingAlgs = objs.hashingAlgs
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
		self.openId4VpVerifierApiUri = openId4VpVerifierApiUri
		self.openId4VpVerifierLegalName = openId4VpVerifierLegalName
		self.urlSession = urlSession
		transactionLog = TransactionLogUtils.initializeTransactionLog(type: .presentation, dataFormat: .json)
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
			case .invalidResolution(error: let error, dispatchDetails: let details):
				logger.error("Invalid resolution: \(error.localizedDescription)")
				if let details { logger.error("Details: \(details)") }
				throw PresentationSession.makeError(str: "Invalid resolution: \(error.localizedDescription)")
			case let .jwt(request: resolvedRequestData):
				self.resolvedRequestData = resolvedRequestData
				switch resolvedRequestData {
				case let .vpToken(vp):
					if let key = vp.clientMetaData?.jwkSet?.keys.first(where: { $0.use == "enc"}), let x = key.x, let xd = Data(base64URLEncoded: x), let y = key.y, let yd = Data(base64URLEncoded: y), let crv = key.crv, let crvType = MdocDataModel18013.CoseEcCurve(crvName: crv)  {
						logger.info("Found jwks public key with curve \(crv)")
						eReaderPub = CoseKey(x: [UInt8](xd), y: [UInt8](yd), crv: crvType)
					}
					let responseUri = if case .directPostJWT(let uri) = vp.responseMode { uri.absoluteString } else { "" }
					vpNonce = vp.nonce; vpClientId = vp.client.id.originalClientId
					mdocGeneratedNonce = Openid4VpUtils.generateMdocGeneratedNonce()
					sessionTranscript = Openid4VpUtils.generateSessionTranscript(clientId: vp.client.id.originalClientId,
						responseUri: responseUri, nonce: vp.nonce, mdocGeneratedNonce: mdocGeneratedNonce)
					logger.info("Session Transcript: \(sessionTranscript.encode().toHexString()), for clientId: \(vp.client.id), responseUri: \(responseUri), nonce: \(vp.nonce), mdocGeneratedNonce: \(mdocGeneratedNonce!)")
					self.presentationDefinition = vp.presentationDefinition
					let (items, fmtsReq, imap) = try Openid4VpUtils.parsePresentationDefinition(vp.presentationDefinition, idsToDocTypes: idsToDocTypes, dataFormats: dataFormats, docDisplayNames: docDisplayNames, logger: logger)
					self.formatsRequested = fmtsReq; self.inputDescriptorMap = imap
					self.transactionData = vp.transactionData
					guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
					var result = UserRequestInfo(docDataFormats: fmtsReq, itemsRequested: items, deviceRequestBytes: try? JSONEncoder().encode(vp.presentationDefinition))
					logger.info("Verifer requested items: \(items.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
					if let ln = resolvedRequestData.legalName { result.readerLegalName = ln }
					if let readerCertificateIssuer {
						result.readerAuthValidated = readerAuthValidated
						result.certificateChain = certificateChain
						result.readerCertificateIssuer = MdocHelpers.getCN(from: readerCertificateIssuer)
						result.readerCertificateValidationMessage = readerCertificateValidationMessage
					}
					TransactionLogUtils.setCborTransactionLogRequestInfo(result, transactionLog: &transactionLog)
					return result
				default: throw PresentationSession.makeError(str: "SiopAuthentication request received, not supported yet.")
				}
			}
	}

	fileprivate func makeCborDocs() {
		docsCbor = docs.filter { k,v in Self.filterFormat(dataFormats[k]!, fmt: .cbor)} .mapValues { IssuerSigned(data: $0.bytes) }.compactMapValues { $0 }
	}

	func generateCborVpToken(itemsToSend: RequestItems) async throws -> (VpToken.VerifiablePresentation, Data, [Data?]) {
		let resp = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, issuerSigned: docsCbor, docDisplayNames: docDisplayNames, docMetadata: docMetadata.compactMapValues { $0 }, selectedItems: itemsToSend, eReaderKey: eReaderPub, devicePrivateKeys: devicePrivateKeys, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: unlockData)
		guard let resp else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		let vpTokenData = Data(resp.deviceResponse.toCBOR(options: CBOROptions()).encode())
		let vpTokenStr = vpTokenData.base64URLEncodedString()
		return (VpToken.VerifiablePresentation.msoMdoc(vpTokenStr), vpTokenData, resp.responseMetadata)
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
			try await SendVpTokens(nil, pd, resolved, onSuccess)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
		if unlockData == nil { _ = try await startQrEngagement(secureAreaName: nil, crv: .P256) }
		if formatsRequested.first(where: { (_, value: DocDataFormat) in value == .cbor }) != nil { makeCborDocs() }
		if formatsRequested.allSatisfy({ (_, value: DocDataFormat) in value == .cbor }) {
			let vpToken = try await generateCborVpToken(itemsToSend: itemsToSend)
			try await SendVpTokens([(pd.inputDescriptors.first!.id, nil, vpToken.0)], pd, resolved, onSuccess)
			TransactionLogUtils.setTransactionLogResponseInfo(deviceResponseBytes: vpToken.1, dataFormat: .cbor, sessionTranscript: Data(sessionTranscript.taggedEncoded.encode(options: CBOROptions())), responseMetadata: vpToken.2, transactionLog: &transactionLog)
		} else {
			let parser = CompactParser()
			let docStrings = docs.filter { k,v in Self.filterFormat(dataFormats[k]!, fmt: .sdjwt)}.compactMapValues { String(data: $0, encoding: .utf8) }
			docsSdJwt = docStrings.compactMapValues { try? parser.getSignedSdJwt(serialisedString: $0) }
			// tuples of inputDescriptor-id, docId and verifiable presentation
			// the inputDescriptor-id is used to identify the input descriptor in the presentation submission
			var inputToPresentations = [(String, String?, VpToken.VerifiablePresentation)]()
			// support sd-jwt documents
			for (docId, nsItems) in itemsToSend {
				guard let docType = idsToDocTypes[docId], let inputDescrId = inputDescriptorMap[docType] else { continue }
				if dataFormats[docId] == .cbor {
					if docsCbor == nil { makeCborDocs() }
					let itemsToSend1 = Dictionary(uniqueKeysWithValues: [(docId, nsItems)])
					let vpToken = try await generateCborVpToken(itemsToSend: itemsToSend1)
					inputToPresentations.append((inputDescrId, docId, vpToken.0))
				} else if dataFormats[docId] == .sdjwt {
					let docSigned = docsSdJwt[docId]; let dpk = devicePrivateKeys[docId]
					guard let docSigned, let dpk, let items = nsItems.first?.value else { continue }
					let unlockData = try await dpk.secureArea.unlockKey(id: docId)
					let keyInfo = try await dpk.secureArea.getKeyInfo(id: docId);	let dsa = keyInfo.publicKey.crv.defaultSigningAlgorithm
					let signer = try SecureAreaSigner(secureArea: dpk.secureArea, id: docId, ecAlgorithm: dsa, unlockData: unlockData)
					let signAlg = try SecureAreaSigner.getSigningAlgorithm(dsa)
					let hai = HashingAlgorithmIdentifier(rawValue: docsHashingAlgs[docId] ?? "") ?? .SHA3256
					guard let presented = try await Openid4VpUtils.getSdJwtPresentation(docSigned, hashingAlg: hai.hashingAlgorithm(), signer: signer, signAlg: signAlg, requestItems: items, nonce: vpNonce, aud: vpClientId, transactionData: transactionData) else {
						continue
					}
					inputToPresentations.append((inputDescrId, docId, VpToken.VerifiablePresentation.generic(presented.serialisation)))
				}
			}
			try await SendVpTokens(inputToPresentations, pd, resolved, onSuccess)
		}
	}
	/// Filter document accordind to the raw format value
	static func filterFormat(_ df: DocDataFormat, fmt: DocDataFormat) -> Bool { df == fmt }

	/// Send the verifiable presentation tokens to the verifier
	/// - Parameters:
	///   - vpTokens: tuples of inputDescriptor-id, docId and verifiable presentation
	///   - pd: input presentation definition
	///   - resolved: Resolved request data
	///   - onSuccess: Callback function to be called on success
	///
	/// - Throws: PresentationSessionError if the presentation submission is not accepted
	fileprivate func SendVpTokens(_ vpTokens: [(String, String?, VpToken.VerifiablePresentation)]?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?) async throws {
		let presentationSubmission: PresentationSubmission? = if let vpTokens { PresentationSubmission(id: UUID().uuidString, definitionID: pd.id, descriptorMap: vpTokens.enumerated().map { i,v in
			 let descr = pd.inputDescriptors.first(where: { $0.id == v.0 })!
			 return DescriptorMap(id: descr.id, format: descr.formatContainer?.formats.first?["designation"].string ?? "", path: vpTokens.count == 1 ? "$" : "$[\(i)]")
			}) } else { nil }
		let consent: ClientConsent = if let vpTokens, let presentationSubmission {
			.vpToken(vpToken: .init(apu: mdocGeneratedNonce.base64urlEncode, verifiablePresentations: vpTokens.map(\.2)), presentationSubmission: presentationSubmission)
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
		if let vpTokens, let presentationSubmission, vpTokens.allSatisfy({ $0.1 != nil }) {
			let docIds = vpTokens.compactMap { $0.1 }
			let responseMetadata: [Data?] = docIds.map { docMetadata[$0].flatMap { $0 } }
			let vpTokenValues = vpTokens.map { $0.2.getString() }
			let responsePayload = VpResponsePayload(verifiable_presentations: vpTokenValues, presentation_submission: presentationSubmission, transaction_data: transactionData)
			TransactionLogUtils.setTransactionLogResponseInfo(deviceResponseBytes: try? JSONEncoder().encode(responsePayload), dataFormat: .json, sessionTranscript: Data(sessionTranscript.taggedEncoded.encode(options: CBOROptions())), responseMetadata: responseMetadata, transactionLog: &transactionLog)
		} else if case let .negative(message) = consent {
			transactionLog = transactionLog.copy(status: .failed, errorMessage: message)
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
		self.certificateChain = data
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

extension VpToken.VerifiablePresentation {
	public func getString() -> String {
		switch self {
		case .generic(let str): return str
		case .msoMdoc(let str): return str
		case .json(let json): return json.stringValue
		}
	}
}
