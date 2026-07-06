/*
Copyright (c) 2026 European Commission

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
import OpenID4VP
import protocol OpenID4VP.Networking
import eudi_lib_sdjwt_swift
import JOSESwift
import Logging
import X509
import SwiftyJSON
import struct OpenID4VP.ClaimPath
import enum OpenID4VP.ClaimPathElement
import struct WalletStorage.Document
/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP specification
public final class OpenId4VpService: @unchecked Sendable, PresentationService {
 	public var status: TransferStatus = .initialized
	var openid4VPlink: String
	let transferInfo: InitializeTransferInfo
	// map of document-id to IssuerSigned
	var docsCbor: [Document.ID: IssuerSigned]!
	// map of document-id to SignedSDJWT
	var docsSdJwt: [Document.ID: SignedSDJWT]!
	var dcqlQueryable: DefaultDcqlQueryable!
	// map of docType to data format (formats requested)
	var formatsRequested: [DocType: DocDataFormat]!
	var transactionData: [TransactionData]?
	/// map of docType to inputDescriptor-id
	var inputDescriptorMap: [String: String]!
	var logger = Logger(label: "OpenId4VpService")
	// Presentation Exchange removed; keep only DCQL
	var dcql: DCQL?
	var resolvedRequestData: ResolvedRequestData?
	var openId4Vp: OpenID4VP!
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
	var zkSpecsRequested: [DocType: [ZkSystemSpec]]?
	var networking: Networking
	var unlockData: [String: Data]!
	var verifierInfo: [VerifierInfo]?
	var docTypeDisplayNames: [DocType: String]
	public var transactionLog: TransactionLog
	public var zkpDocumentIds: [WalletStorage.Document.ID]?
	public var flow: FlowType
	public let crlRevocationPolicy: RevocationPolicy

	public init(
		parameters: InitializeTransferData,
		qrCode: Data,
		openID4VpConfig: OpenId4VpConfiguration,
		networking: Networking,
		crlRevocationPolicy: RevocationPolicy,
		docTypeDisplayNames: [DocType: String] = [:]
	) async throws {
		self.flow = .openid4vp(qrCode: qrCode)
		let objs = try await parameters.toInitializeTransferInfo()
		self.transferInfo = objs
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
		self.openID4VpConfig = openID4VpConfig
		self.networking = networking
		self.crlRevocationPolicy = crlRevocationPolicy
		self.docTypeDisplayNames = docTypeDisplayNames
		transactionLog = TransactionLogUtils.initializeTransactionLog(type: .presentation, dataFormat: .json)
	}

	public func startQrEngagement(secureAreaName: String?, keyOptions: KeyOptions) async throws -> String {
		if unlockData == nil {
			unlockData = [String: Data]()
			for (id, key) in transferInfo.privateKeyObjects {
				let ud = try await key.secureArea.unlockKey(id: id)
				if let ud { unlockData[id] = ud }
			}
		}
		return ""
	}

	///  Receive request from an openid4vp URL
	///
	/// - Returns: The requested items.
	public func receiveRequest() async throws -> [UserRequestInfo] {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw PresentationSession.makeError(str: "Invalid link \(openid4VPlink)") }
		openId4Vp = OpenID4VP(walletConfiguration: getWalletConf())
		switch await openId4Vp.authorize(fetcher: Fetcher<String>(session: networking), poster: Poster(session: networking), url: openid4VPURI)  {
		case .notSecured(data: let rrd):
			if case .redirectUri = rrd.client { return try handleRequestData(rrd) }
			else { throw PresentationSession.makeError(str: "Not secured request") }
		case .invalidResolution(error: let error, dispatchDetails: let details):
			logger.error("Invalid resolution: \(error.errorDescription ?? error.localizedDescription)")
			if let details { logger.error("Details: \(details)") }
			throw PresentationSession.makeError(str: "Invalid DCQL query: \(error.errorDescription ?? error.localizedDescription)")
		case let .jwt(request: rrd):
			return try handleRequestData(rrd)
		}
	}

	func handleRequestData(_ rrd: ResolvedRequestData) throws -> [UserRequestInfo] {
		self.resolvedRequestData = rrd
		let vp = rrd.request
		var jwkThumbprint: Data?  = nil

		if let key = vp.clientMetaData?.jwkSet?.keys.first(where: { $0.use == "enc"}),
			let x = key.x, let xd = Data(base64URLEncoded: x),
			let y = key.y, let yd = Data(base64URLEncoded: y),
			let crv = key.crv,
			let crvType = MdocDataModel18013.CoseEcCurve(crvName: crv),
			let ecCrvType = ECCurveType(rawValue: crv) {
			logger.info("Found jwks public key with curve \(crv)")
			eReaderPub = CoseKey(x: [UInt8](xd), y: [UInt8](yd), crv: crvType)
			// Generate a jwkThumbprint if possible.
			let publicKey = ECPublicKey(crv: ecCrvType, x: x , y: y)
			jwkThumbprint = (try? publicKey.thumbprint(algorithm: .SHA256)).flatMap { Data(base64URLEncoded: $0) }
		}
		// Add support for directPost.
		let responseUri = if case .directPostJWT(let uri) = vp.responseMode { uri.absoluteString } else if case .directPost(let uri) = vp.responseMode { uri.absoluteString } else { "" }
		let resolvedClientId = vp.client.id.clientId
		vpNonce = vp.nonce; vpClientId = resolvedClientId
		mdocGeneratedNonce = OpenId4VpUtils.generateMdocGeneratedNonce()	// Not longer required for SessionTranscript, use the verifier (client) nonce i.e vpNonce
		sessionTranscript = SessionTranscript(handOver: OpenId4VpUtils.generateOpenId4VpHandover(clientId: resolvedClientId, responseUri: responseUri, nonce: vpNonce, jwkThumbprint: jwkThumbprint?.byteArray))
		transactionData = vp.transactionData
		verifierInfo = vp.verifierInfo

		logger.info("Session Transcript: \(sessionTranscript.encode().toHexString()), for clientId: \(vp.client.id), responseUri: \(responseUri), nonce: \(vp.nonce), mdocGeneratedNonce: \(mdocGeneratedNonce!)")
		// Only DCQL supported now
		if case let .byDigitalCredentialsQuery(dcql) = vp.presentationQuery {
			self.dcql = dcql
			let deviceRequestBytes = try? JSONEncoder().encode(dcql)
			let (fmtsReq, imap, zkSpecMap) = try OpenId4VpUtils.parseDcqlFormats(dcql, idsToDocTypes: transferInfo.idsToDocTypes, logger: logger)
			formatsRequested = fmtsReq; inputDescriptorMap = imap; zkSpecsRequested = zkSpecMap
			decodeDocuments()
			let credentialSelectionSets = try OpenId4VpUtils.resolveDcql(
				dcql, queryable: dcqlQueryable, allowPresentingPartialClaims: openID4VpConfig.allowPresentingPartialClaims, docTypeDisplayNames: docTypeDisplayNames)
			let requestItemsArray = OpenId4VpUtils.getRequestItems(credentialSelectionSets, idsToDocTypes: transferInfo.idsToDocTypes, formatsRequested: formatsRequested)
			let transactionDataRequestedArray = transactionData != nil
				? try OpenId4VpUtils.getTransactionDataRequested(
					credentialSelectionSets,
					transactionDataList: transactionData!)
				: nil
			let verifierInfoRequestedArray = verifierInfo != nil
				? OpenId4VpUtils.getVerifierInfoRequested(credentialSelectionSets, verifierInfoList: verifierInfo!)
				: nil
			let certificateIssuerName = readerCertificateIssuer.map(MdocHelpers.getCN(from:))
			let rar = ReaderAuthenticationResult(isValidated: readerAuthValidated, certificateIssuer: certificateIssuerName, validationMessage: readerCertificateValidationMessage, legalName: rrd.legalName, authBytes: nil, certificateChain: certificateChain)
			var results = [UserRequestInfo]()
			for (requestName, requestItems) in requestItemsArray {
				let transactionDataRequested = transactionDataRequestedArray?.first(where: { $0.0 == requestName })
				let verifierInfoRequested = verifierInfoRequestedArray?.first(where: { $0.0 == requestName })
				//guard let requestItems, let formatsRequested else { throw PresentationSession.makeError(str: "Invalid request query") }
				var result = UserRequestInfo(
					docDataFormats: formatsRequested,
					itemsRequested: requestItems,
					deviceRequestBytes: deviceRequestBytes,
					transactionDataRequested: transactionDataRequested?.1,
					verifierInfo: verifierInfoRequested?.1,
					requestName: requestName
				)
				logger.info("Verifier requested items: \(requestItems.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
				result.readerAuthResults = ["": rar]
				TransactionLogUtils.setCborTransactionLogRequestInfo(result, transactionLog: &transactionLog)
				results.append(result)
			}
			return results
		} else { throw PresentationSession.makeError(str: "Unsupported presentation query") }
	}

	fileprivate func makeCborDocs() {
		docsCbor = transferInfo.documentObjects.filter { k,v in Self.filterFormat(transferInfo.dataFormats[k]!, fmt: .cbor)} .mapValues { try? IssuerSigned(data: $0.bytes) }.compactMapValues { $0 }
	}

	func generateCborVpToken(itemsToSend: RequestItems, deviceNameSpacesToSend: RequestDeviceNameSpaces?) async throws -> (VerifiablePresentation, Data, [Data?], [String]) {
		let docMetadata = transferInfo.docMetadata
		let privateKeyObjects = transferInfo.privateKeyObjects
		let zkSystemRepository = transferInfo.zkSystemRepository
		let resp = try await MdocHelpers.getDeviceResponseToSend(
			deviceRequest: nil,
			issuerSigned: docsCbor,
			docMetadata: docMetadata,
			selectedItems: itemsToSend,
			eReaderKey: eReaderPub,
			privateKeyObjects: privateKeyObjects,
			sessionTranscript: sessionTranscript,
			dauthMethod: .deviceSignature,
			unlockData: unlockData,
			zkSpecsRequested: zkSpecsRequested,
			zkSystemRepository: zkSystemRepository,
			deviceNameSpacesRequested: deviceNameSpacesToSend)
		guard let resp else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		let vpTokenData = Data(resp.deviceResponse.toCBOR(options: CBOROptions()).encode())
		let vpTokenStr = vpTokenData.base64URLEncodedString()
		return (VerifiablePresentation.generic(vpTokenStr), vpTokenData, resp.responseMetadata, resp.zkpDocumentIds)
	}

	func decodeDocuments() {
		if formatsRequested.first(where: { (_, value: DocDataFormat) in value == .cbor }) != nil { makeCborDocs() }
		let parser = CompactParser()
		let docJwtStrings = transferInfo.documentObjects.filter { k,v in Self.filterFormat(transferInfo.dataFormats[k]!, fmt: .sdjwt)}.compactMapValues { String(data: $0, encoding: .utf8) }
		docsSdJwt = docJwtStrings.compactMapValues { try? parser.getSignedSdJwt(serialisedString: $0) }
		// make dcqlQueryable
		let credentialMap = OpenId4VpUtils.makeCredentialMap(
			idsToDocTypes: transferInfo.idsToDocTypes,
			formatsRequested: formatsRequested
		)
		var claimPaths = [Document.ID: [ClaimPath]]()
		var claimValues = [Document.ID: [ClaimPath: [String]]]()
		OpenId4VpUtils.makeCborClaimData(from: docsCbor, claimPaths: &claimPaths, claimValues: &claimValues)
		OpenId4VpUtils.makeSdJwtClaimData(from: docsSdJwt, claimPaths: &claimPaths, claimValues: &claimValues)
		dcqlQueryable = DefaultDcqlQueryable(credentials: credentialMap, claimPaths: claimPaths, claimValues: claimValues)
	}

	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	///   - deviceNameSpacesToSend: Optional device-signed namespaces to include in the response
	///   - onSuccess: Callback invoked on successful response with an optional redirect URL
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, deviceNameSpacesToSend: RequestDeviceNameSpaces? = nil, onSuccess: ((URL?) -> Void)?) async throws {
		guard dcql != nil, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpTokens(nil, dcql, resolved, onSuccess)
			return
		}
		zkpDocumentIds = [String]()
		logger.info("Openid4vp request items: \(itemsToSend.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
		if unlockData == nil { _ = try await startQrEngagement(secureAreaName: nil, keyOptions: KeyOptions(curve: .P256)) }
		// tuples of inputDescriptor-id, docId and verifiable presentation
		// the inputDescriptor-id is used to identify the input descriptor in the presentation submission
		var inputToPresentations = [(String, String?, VerifiablePresentation)]()
		// support sd-jwt documents
		for (docId, nsItems) in itemsToSend {
			guard let docType = transferInfo.idsToDocTypes[docId], let inputDescrId = inputDescriptorMap[docType] else { continue }
			if transferInfo.dataFormats[docId] == .cbor {
				if docsCbor == nil { makeCborDocs() }
				let itemsToSend1 = Dictionary(uniqueKeysWithValues: [(docId, nsItems)])
				let vpToken = try await generateCborVpToken(itemsToSend: itemsToSend1, deviceNameSpacesToSend: deviceNameSpacesToSend)
				zkpDocumentIds!.append(contentsOf: vpToken.3)
				inputToPresentations.append((inputDescrId, docId, vpToken.0))
			} else if transferInfo.dataFormats[docId] == .sdjwt {
				let docSigned = docsSdJwt[docId]; let dpk = transferInfo.privateKeyObjects[docId]
				let docData = transferInfo.documentObjects[docId]
				guard let docSigned, let docData, let dpk, let items = nsItems.first?.value else { continue }
				guard let holderPublicJwk = try SdJwtUtils.parseCnfBindingKeys(fromDocumentData: docData).first else { continue }
				let unlockData = try await dpk.secureArea.unlockKey(id: docId)
				let keyInfo = try await dpk.secureArea.getKeyBatchInfo(id: docId)
				let dsa = keyInfo.crv.defaultSigningAlgorithm
				let signer = try SecureAreaSigner(secureArea: dpk.secureArea, id: docId, index: dpk.index, publicKey: holderPublicJwk, curve: keyInfo.crv, ecAlgorithm: dsa, unlockData: unlockData)
				let signAlg = try SecureAreaSigner.getSigningAlgorithm(dsa)
				let hai = HashingAlgorithmIdentifier(rawValue: transferInfo.hashingAlgs[docId] ?? "") ?? .SHA3256
				guard let presented = try await OpenId4VpUtils.getSdJwtPresentation(docSigned, hashingAlg: hai.hashingAlgorithm(), signer: signer, signAlg: signAlg, requestItems: items, nonce: vpNonce, aud: vpClientId, transactionData: transactionData) else {
					continue
				}
				inputToPresentations.append((inputDescrId, docId, VerifiablePresentation.generic(presented.serialisation)))
			}
		}
		try await SendVpTokens(inputToPresentations, dcql, resolved, onSuccess)

	}

	public func waitForDisconnect() async throws {
		status = .disconnected
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
			.vpToken(vpContent: .dcql(verifiablePresentations: Dictionary(grouping: vpTokens, by: { try! QueryId(value: $0.0) }).mapValues { $0.map { $0.2 } } ))
		} else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response, applying wallet-preferred response mode if configured
		let response = try buildAuthorizationResponse(resolved: resolved, consent: consent)
		let result: DispatchOutcome = try await openId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
			onSuccess?(url)
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
		if let vpTokens, dcql != nil, vpTokens.allSatisfy({ $0.1 != nil }) {
			let data_formats: [DocDataFormat]? = if let dcql, case let .vpToken(vpContent) = consent, case let .dcql(vp) = vpContent { vp.flatMap { (queryId, vps) in Array(repeating: dcql.findQuery(id: queryId.value)!.dataFormat, count: vps.count) } } else { nil }
			// Build responseMetadata and vpTokenValues aligned by iterating vp in the same order
			var responseMetadata = [Data?]()
			var vpTokenValues = [String]()
			if case let .vpToken(vpContent) = consent, case let .dcql(vp) = vpContent {
				for (queryId, vps) in vp {
					for vp in vps {
						vpTokenValues.append(vp.getString())
					}
					// Find doc IDs for this query by matching inputDescriptorMap
					let queryDocIds = vpTokens.filter { try! QueryId(value: $0.0) == queryId }.compactMap { $0.1 }
					for docId in queryDocIds {
						responseMetadata.append(transferInfo.docMetadata[docId])
					}
				}
			}
			let responsePayload = VpResponsePayload(verifiable_presentations: vpTokenValues, data_formats: data_formats, transaction_data: transactionData)
			TransactionLogUtils.setTransactionLogResponseInfo(deviceResponseBytes: try? JSONEncoder().encode(responsePayload), dataFormat: .json, sessionTranscript: Data(sessionTranscript.taggedEncoded.encode(options: CBOROptions())), responseMetadata: responseMetadata, transactionLog: &transactionLog)
		} else if case let .negative(message) = consent {
			transactionLog = transactionLog.copy(status: .failed, errorMessage: message)
		}
	}

	lazy var chainVerifier: CertificateTrust = { [weak self] certificates async -> Bool in
		guard let self else { return false }
		var isValid: Bool = false; var validationMessages: [String] = []
		let b64certs = certificates; let certsData = b64certs.compactMap { Data(base64Encoded: $0) }
		let certsDer = certsData.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		guard certsDer.count > 0, certsDer.count == b64certs.count else { return false }
		guard let x509leaf = try? X509.Certificate(derEncoded: [UInt8](certsData.first!)) else { return false }
		guard let x509 = try? X509.Certificate(derEncoded: [UInt8](certsData.last!)) else { return false }
		let policy = SecPolicyCreateBasicX509(); var trust: SecTrust?; var result: OSStatus
		result = SecTrustCreateWithCertificates(certsDer as CFArray, policy, &trust)
		guard result == errSecSuccess, let trust else { logger.error("Chain verification error: \(result.message)"); return false }
		self.readerCertificateIssuer = x509.subject.description
		(isValid, validationMessages, _) = SecurityHelpers
			.isMdocX5cValid(secCerts: certsDer, usage: .mdocReaderAuth, revocationPolicy: crlRevocationPolicy, rootIaca: transferInfo.iaca)
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = validationMessages.joined(separator: "\n")
		self.certificateChain = certsData
		return isValid
	}

	/// OpenId4VP wallet configuration
	func getWalletConf() -> OpenId4VPConfiguration? {
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
		let res = OpenId4VPConfiguration(
			privateKey: privateKey,
			publicWebKeySet: keySet,
			supportedClientIdSchemes: supportedClientIdPrefixes,
			vpFormatsSupported: [],
			jarConfiguration: .encryptionOption,
			vpConfiguration: try! .init(
				vpFormatsSupported: .default(),
				supportedTransactionDataTypes: openID4VpConfig.supportedTransactionDataTypes),
			errorDispatchPolicy: .allClients,
			session: networking,
			responseEncryptionConfiguration: openID4VpConfig.responseEncryptionConfiguration ?? .default())
		return res
	}

	/// Builds an `AuthorizationResponse` applying the wallet's preferred response mode if configured.
	/// When `preferredResponseMode` is set, overrides the verifier's requested mode while keeping the response URI from the request.
	/// When not set, delegates to the standard `AuthorizationResponse` init (current behavior).
	func buildAuthorizationResponse(resolved: ResolvedRequestData, consent: ClientConsent) throws -> AuthorizationResponse {
		guard let preferred = openID4VpConfig.preferredResponseMode else {
			return try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(), encryptionParameters: .apu(mdocGeneratedNonce.base64urlEncode))
		}
		let request = resolved.request
		// Extract the response URI from the request's response mode
		let responseURI: URL? = switch request.responseMode {
		case .directPost(let uri): uri
		case .directPostJWT(let uri): uri
		case .query(let uri): uri
		case .fragment(let uri): uri
		case .some(.none), nil: nil
		}
		guard let uri = responseURI else {
			return try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(), encryptionParameters: .apu(mdocGeneratedNonce.base64urlEncode))
		}
		let payload: AuthorizationResponsePayload
		switch consent {
		case .vpToken(let vpContent):
			payload = .openId4VPAuthorizationResponse(
				vpContent: vpContent,
				state: request.state ?? "",
				nonce: request.nonce,
				clientId: resolved.client.id,
				encryptionParameters: .apu(mdocGeneratedNonce.base64urlEncode)
			)
		case .negative(let error):
			guard let state = request.state else { throw PresentationSession.makeError(str: "Missing state in request") }
			payload = .noConsensusResponseData(state: state, error: error)
		}
		switch preferred {
		case .directPost:
			return .directPost(url: uri, data: payload)
		case .directPostJWT:
			guard let spec = request.responseEncryptionSpecification else {
				throw PresentationSession.makeError(str: "directPostJWT requires response encryption specification from verifier")
			}
			return .directPostJwt(url: uri, data: payload, responseEncryptionSpecification: spec)
		}
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

