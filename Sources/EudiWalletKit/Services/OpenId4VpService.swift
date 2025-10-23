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
import SiopOpenID4VP
import protocol SiopOpenID4VP.Networking
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
	var privateKeyObjects: [String: CoseKeyPrivate]!
	var logger = Logger(label: "OpenId4VpService")
	// Presentation Exchange removed; keep only DCQL
	var dcql: DCQL?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var openID4VpConfig: OpenId4VpConfiguration
	var readerAuthValidated: Bool = false
	var readerCertificateIssuer: String?
	var readerCertificateValidationMessage: String?
	var certificateChain: [Data]?
	var vpNonce: String!
	var vpClientId: String!
	var mdocGeneratedNonce: String!
	var sessionTranscript: SessionTranscript!
	var eReaderPub: CoseKey?
	var networking: Networking
	var unlockData: [String: Data]!
	public var transactionLog: TransactionLog
	public var flow: FlowType

	public init(parameters: InitializeTransferData, qrCode: Data, openID4VpConfig: OpenId4VpConfiguration, networking: Networking) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		let objs = parameters.toInitializeTransferInfo()
		dataFormats = objs.dataFormats; docs = objs.documentObjects; privateKeyObjects = objs.privateKeyObjects
		iaca = objs.iaca; dauthMethod = objs.deviceAuthMethod
		docMetadata = parameters.docMetadata
		idsToDocTypes = objs.idsToDocTypes
		docDisplayNames = objs.docDisplayNames
		docsHashingAlgs = objs.hashingAlgs
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
		self.openID4VpConfig = openID4VpConfig
		self.networking = networking
		transactionLog = TransactionLogUtils.initializeTransactionLog(type: .presentation, dataFormat: .json)
	}

	public func startQrEngagement(secureAreaName: String?, crv: CoseEcCurve) async throws -> String {
		if unlockData == nil {
			unlockData = [String: Data]()
			for (id, key) in privateKeyObjects {
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
		siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: getWalletConf())
		switch await siopOpenId4Vp.authorize(url: openid4VPURI)  {
		case .notSecured(data: let rrd):
			if case .redirectUri = rrd.client { return try handleRequestData(rrd) }
			else { throw PresentationSession.makeError(str: "Not secured request") }
		case .invalidResolution(error: let error, dispatchDetails: let details):
			logger.error("Invalid resolution: \(error.localizedDescription)")
			if let details { logger.error("Details: \(details)") }
			throw PresentationSession.makeError(str: "Invalid resolution: \(error.localizedDescription)")
		case let .jwt(request: rrd):
			return try handleRequestData(rrd)
		}
	}

	func handleRequestData(_ rrd: ResolvedRequestData) throws -> UserRequestInfo {
		self.resolvedRequestData = rrd
		switch rrd {
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
			var requestItems: RequestItems?; var deviceRequestBytes: Data?
			// Only DCQL supported now
			if case let .byDigitalCredentialsQuery(dcql) = vp.presentationQuery {
				self.dcql = dcql
				deviceRequestBytes = try? JSONEncoder().encode(dcql)
				let (items, fmtsReq, imap) = try Openid4VpUtils.parseDcql(dcql, idsToDocTypes: idsToDocTypes, dataFormats: dataFormats, docDisplayNames: docDisplayNames, logger: logger)
				formatsRequested = fmtsReq; inputDescriptorMap = imap; requestItems = items
			}
			self.transactionData = vp.transactionData
			guard let requestItems, let formatsRequested else { throw PresentationSession.makeError(str: "Invalid request query") }
			var result = UserRequestInfo(docDataFormats: formatsRequested, itemsRequested: requestItems, deviceRequestBytes: deviceRequestBytes)
			logger.info("Verifier requested items: \(requestItems.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
			if let ln = rrd.legalName { result.readerLegalName = ln }
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

	fileprivate func makeCborDocs() {
		docsCbor = docs.filter { k,v in Self.filterFormat(dataFormats[k]!, fmt: .cbor)} .mapValues { try? IssuerSigned(data: $0.bytes) }.compactMapValues { $0 }
	}

	func generateCborVpToken(itemsToSend: RequestItems) async throws -> (VerifiablePresentation, Data, [Data?]) {
		let resp = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, issuerSigned: docsCbor, docMetadata: docMetadata.compactMapValues { $0 }, selectedItems: itemsToSend, eReaderKey: eReaderPub, privateKeyObjects: privateKeyObjects, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature, unlockData: unlockData)
		guard let resp else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		let vpTokenData = Data(resp.deviceResponse.toCBOR(options: CBOROptions()).encode())
		let vpTokenStr = vpTokenData.base64URLEncodedString()
		return (VerifiablePresentation.generic(vpTokenStr), vpTokenData, resp.responseMetadata)
	}

	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws {
		guard dcql != nil, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpTokens(nil, dcql, resolved, onSuccess)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
		if unlockData == nil { _ = try await startQrEngagement(secureAreaName: nil, crv: .P256) }
		if formatsRequested.first(where: { (_, value: DocDataFormat) in value == .cbor }) != nil { makeCborDocs() }
		let parser = CompactParser()
		let docStrings = docs.filter { k,v in Self.filterFormat(dataFormats[k]!, fmt: .sdjwt)}.compactMapValues { String(data: $0, encoding: .utf8) }
		docsSdJwt = docStrings.compactMapValues { try? parser.getSignedSdJwt(serialisedString: $0) }
		// tuples of inputDescriptor-id, docId and verifiable presentation
		// the inputDescriptor-id is used to identify the input descriptor in the presentation submission
		var inputToPresentations = [(String, String?, VerifiablePresentation)]()
		// support sd-jwt documents
		for (docId, nsItems) in itemsToSend {
			guard let docType = idsToDocTypes[docId], let inputDescrId = inputDescriptorMap[docType] else { continue }
			if dataFormats[docId] == .cbor {
				if docsCbor == nil { makeCborDocs() }
				let itemsToSend1 = Dictionary(uniqueKeysWithValues: [(docId, nsItems)])
				let vpToken = try await generateCborVpToken(itemsToSend: itemsToSend1)
				inputToPresentations.append((inputDescrId, docId, vpToken.0))
			} else if dataFormats[docId] == .sdjwt {
				let docSigned = docsSdJwt[docId]; let dpk = privateKeyObjects[docId]
				guard let docSigned, let dpk, let items = nsItems.first?.value else { continue }
				let unlockData = try await dpk.secureArea.unlockKey(id: docId)
				let keyInfo = try await dpk.secureArea.getKeyBatchInfo(id: docId)
				let dsa = keyInfo.crv.defaultSigningAlgorithm
				let signer = try SecureAreaSigner(secureArea: dpk.secureArea, id: docId, index: dpk.index, ecAlgorithm: dsa, unlockData: unlockData)
				let signAlg = try SecureAreaSigner.getSigningAlgorithm(dsa)
				let hai = HashingAlgorithmIdentifier(rawValue: docsHashingAlgs[docId] ?? "") ?? .SHA3256
				guard let presented = try await Openid4VpUtils.getSdJwtPresentation(docSigned, hashingAlg: hai.hashingAlgorithm(), signer: signer, signAlg: signAlg, requestItems: items, nonce: vpNonce, aud: vpClientId, transactionData: transactionData) else {
					continue
				}
				inputToPresentations.append((inputDescrId, docId, VerifiablePresentation.generic(presented.serialisation)))
			}
		}
		try await SendVpTokens(inputToPresentations, dcql, resolved, onSuccess)

	}
	/// Filter document accordind to the raw format value
	static func filterFormat(_ df: DocDataFormat, fmt: DocDataFormat) -> Bool { df == fmt }

	/// Send the verifiable presentation tokens to the verifier
	/// - Parameters:
	///   - vpTokens: tuples of query-id, docId and verifiable presentation
	///   - dcql: DCQL query
	///   - resolved: Resolved request data
	///   - onSuccess: Callback function to be called on success
	///
	/// - Throws: PresentationSessionError if the presentation submission is not accepted
	fileprivate func SendVpTokens(_ vpTokens: [(String, String?, VerifiablePresentation)]?, _ dcql: DCQL?, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?) async throws {
		let consent: ClientConsent = if let vpTokens, dcql != nil {
			// Group by DCQL query id -> array of VPs
			.vpToken(vpContent: .dcql(verifiablePresentations: Dictionary(grouping: vpTokens, by: { try! QueryId(value: $0.0) }).mapValues { $0.map { $0.2 } }))
		} else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(), encryptionParameters: .apu(mdocGeneratedNonce.base64urlEncode))
		let result: DispatchOutcome = try await siopOpenId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
			onSuccess?(url)
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
		if let vpTokens, dcql != nil, vpTokens.allSatisfy({ $0.1 != nil }) {
			let docIds = vpTokens.compactMap { $0.1 }
			let data_formats: [DocDataFormat]? = if let dcql, case let .vpToken(vpContent) = consent, case let .dcql(vp) = vpContent { vp.keys.map { dcql.findQuery(id: $0.value)!.dataFormat} } else { nil }
			let responseMetadata: [Data?] = docIds.map { docMetadata[$0].flatMap { $0 } }
			let vpTokenValues: [String]? = if case let .vpToken(vpContent) = consent, case let .dcql(vp) = vpContent {  vp.values.flatMap { $0.map { $0.getString() } } } else  { nil }
			let responsePayload = VpResponsePayload(verifiable_presentations: vpTokenValues!, data_formats: data_formats, transaction_data: transactionData)
			TransactionLogUtils.setTransactionLogResponseInfo(deviceResponseBytes: try? JSONEncoder().encode(responsePayload), dataFormat: .json, sessionTranscript: Data(sessionTranscript.taggedEncoded.encode(options: CBOROptions())), responseMetadata: responseMetadata, transactionLog: &transactionLog)
		} else if case let .negative(message) = consent {
			transactionLog = transactionLog.copy(status: .failed, errorMessage: message)
		}
	}

	lazy var chainVerifier: CertificateTrust = { [weak self] certificates in
		guard let self else { return false }
		let b64certs = certificates; let certsData = b64certs.compactMap { Data(base64Encoded: $0) }
		let certsDer = certsData.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		guard certsDer.count > 0, certsDer.count == b64certs.count else { return false }
		guard let x509 = try? X509.Certificate(derEncoded: [UInt8](certsData.first!)) else { return false }
		let policy = SecPolicyCreateBasicX509(); var trust: SecTrust?; var result: OSStatus
		result = SecTrustCreateWithCertificates(certsDer as CFArray, policy, &trust)
		guard result == errSecSuccess, let trust else { logger.error("Chain verification error: \(result.message)"); return false }
		self.readerCertificateIssuer = x509.subject.description
		let (isValid, validationMessages, _) = SecurityHelpers.isMdocX5cValid(secCerts: certsDer, usage: .mdocReaderAuth, rootCerts: self.iaca ?? [])
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = validationMessages.joined(separator: "\n")
		self.certificateChain = certsData
		return isValid
	}

	/// OpenId4VP wallet configuration
	func getWalletConf() -> SiopOpenId4VPConfiguration? {
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
		let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
		let supportedClientIdPrefixes: [SupportedClientIdPrefix] = openID4VpConfig.clientIdSchemes.map { cids in
			switch cids {
				case .redirectUri: .redirectUri
				case .x509Hash: .x509Hash(trust: chainVerifier)
				case .x509SanDns: .x509SanDns(trust: chainVerifier)
				case .preregistered(let clients): .preregistered(clients: Dictionary(uniqueKeysWithValues: clients.map { ($0.clientId, $0) }))
			}
		}
		let res = SiopOpenId4VPConfiguration(subjectSyntaxTypesSupported: [.decentralizedIdentifier, .jwkThumbprint], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), privateKey: privateKey, publicWebKeySet: keySet, supportedClientIdSchemes: supportedClientIdPrefixes, vpFormatsSupported: [],  jarConfiguration: .encryptionOption, vpConfiguration: .default(), session: networking, responseEncryptionConfiguration: .default())
		return res
	}

}

extension VerifiablePresentation {
	public func getString() -> String {
		switch self {
		case .generic(let str): return str
		case .json(let json): return json.stringValue
		}
	}
}

struct OpenID4VPNetworking: Networking {
	let networking: any NetworkingProtocol

	init(networking: any NetworkingProtocol) {
		self.networking = networking
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		try await networking.data(from: url)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		try await networking.data(for: request)
	}
}

