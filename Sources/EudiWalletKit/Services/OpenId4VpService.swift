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
import os
@preconcurrency import LocalAuthentication
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
import struct OpenID4VP.ClaimPath
import enum OpenID4VP.ClaimPathElement
import struct WalletStorage.Document
import struct OpenID4VP.PolicyViolation
/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP specification
public final class OpenId4VpService: @unchecked Sendable, PresentationService {
	public var status: TransferStatus = .initialized
	var openid4VPlink: String
	let transferInfo: InitializeTransferInfo
	/// COSE algorithm used for mdoc device signatures
	public let deviceAlgorithm: Cose.VerifyAlgorithm
	// map of document-id to IssuerSigned
	var docsCbor: [Document.ID: IssuerSigned]!
	// map of document-id to SignedSDJWT
	var docsSdJwt: [Document.ID: SignedSDJWT]!
	var dcqlQueryable: DefaultDcqlQueryable!
	// map of docType to data format (formats requested)
	var formatsRequested: [DocType: DocDataFormat]!
	var transactionData: [TransactionData]?
	var parsedTransactionData: [PresentationTransactionData] = []
	var credentialSelections: CredentialSelectionSetOptions = [:]
	var transactionAssignments: [String: [TransactionDataProcessor.Assignment]] = [:]
	/// Typed transaction data for each presentation option and wallet document.
	public private(set) var transactionDataByRequest: [String: [String: [PresentationTransactionData]]] = [:]
	/// map of docType to inputDescriptor-id
	var inputDescriptorMap: [String: String]!
	var logger = Logger(label: "OpenId4VpService")
	// Presentation Exchange removed; keep only DCQL
	var dcql: DCQL?
	var resolvedRequestData: ResolvedRequestData?
	var openId4Vp: OpenID4VP!
	var openID4VpConfig: OpenId4VpConfiguration
	/// Complete request authentication; certificate trust alone does not establish this verdict.
	public private(set) var readerAuthenticationStatus: ReaderAuthenticationStatus = .notEvaluated
	private let requestOperationLock = OSAllocatedUnfairLock(initialState: false)
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
	public var wrpVerifierPolicy: WrpRegistrationPolicy?
	public var wrpVerifierWarnings: [String: [PresentationPolicyViolation]]?
	public var transactionLogger: (any TransactionLogger)?
	public var transactionLog: TransactionEntry
	public var zkpDocumentIds: [WalletStorage.Document.ID]?
	public private(set) var presentedDocumentIds: [WalletStorage.Document.ID] = []
	public var flow: FlowType
	/// Trust configuration used to validate the reader/relying-party access certificate chain.
	public let trustConfig: TrustConfiguration
	public let wrpRegistrationValidator: WrpVpRegistrationValidator

	public init(
		parameters: InitializeTransferData,
		qrCode: Data,
		openID4VpConfig: OpenId4VpConfiguration,
		networking: Networking,
		trustConfig: TrustConfiguration,
		wrpRegistrationValidator: WrpVpRegistrationValidator,
		docTypeDisplayNames: [DocType: String] = [:],
		deviceAlgorithm: Cose.VerifyAlgorithm = .es256
	) async throws {
		self.flow = .openid4vp(qrCode: qrCode)
		let objs = try await parameters.toInitializeTransferInfo()
		self.transferInfo = objs
		self.deviceAlgorithm = deviceAlgorithm
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw WalletError(description: "QR_DATA_MALFORMED", code: .invalidQueryResolution)
		}
		self.openid4VPlink = openid4VPlink
		self.openID4VpConfig = openID4VpConfig
		self.networking = networking
		self.trustConfig = trustConfig
		self.wrpRegistrationValidator = wrpRegistrationValidator
		self.docTypeDisplayNames = docTypeDisplayNames
		transactionLog = TransactionLogUtils.createEmptyPresentationLog()
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
		try beginRequestOperation()
		defer { endRequestOperation() }
		resetPresentationState()
		do {
			return try await resolveRequest()
		} catch {
			readerAuthenticationStatus = .failed
			resolvedRequestData = nil
			dcql = nil
			vpNonce = nil; vpClientId = nil; sessionTranscript = nil; eReaderPub = nil
			throw error
		}
	}

	private func resetPresentationState() {
		readerAuthenticationStatus = .notEvaluated
		readerAuthValidated = false
		readerCertificateIssuer = nil
		readerCertificateValidationMessage = nil
		certificateChain = nil
		resolvedRequestData = nil
		dcql = nil
		vpNonce = nil; vpClientId = nil; sessionTranscript = nil; eReaderPub = nil
		wrpVerifierPolicy = nil; wrpVerifierWarnings = nil
		formatsRequested = nil; inputDescriptorMap = nil; zkSpecsRequested = nil
		transactionData = nil; verifierInfo = nil; dcqlQueryable = nil; mdocGeneratedNonce = nil
		presentedDocumentIds = []
	}

	// Reserve mutable request/callback state across suspension points without holding a lock.
	private func beginRequestOperation() throws {
		try requestOperationLock.withLock { inProgress in
			guard !inProgress else {
				throw WalletError(description: "A presentation request operation is already in progress", code: .invalidQueryResolution)
			}
			inProgress = true
		}
	}

	private func endRequestOperation() {
		requestOperationLock.withLock { $0 = false }
	}

	private func resolveRequest() async throws -> [UserRequestInfo] {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw WalletError(description: "Invalid link \(openid4VPlink)", code: .invalidQueryResolution) }
		let dcqlQ = decodeDocuments()
		await wrpRegistrationValidator.resetValidations()
		await wrpRegistrationValidator.set(dcqlQueryable: dcqlQ)
		openId4Vp = OpenID4VP(walletConfiguration: getWalletConf(), authorizatinRequestResolver: WalletAuthorizationRequestResolver())
		switch await openId4Vp.authorize(fetcher: Fetcher<String>(session: networking), poster: Poster(session: networking), url: openid4VPURI)  {
		case let .notSecured(data: rrd, warnings):
			self.wrpVerifierWarnings = await wrpRegistrationValidator.wrpVpWarnings
			if !warnings.isEmpty { logger.warning("Policy warnings: \(warnings.mapValues{$0.map(\.violation)})") }
			guard case .redirectUri = rrd.client else { throw WalletError(description: "Not secured request", code: .notSecuredRequest) }
			let requests = try await handleRequest(rrd)
			readerAuthenticationStatus = .notApplicable
			return requests
		case .invalidResolution(error: let error, dispatchDetails: let details):
			logger.error("Invalid resolution: \(error.errorDescription ?? error.localizedDescription)")
			if let details {
				logger.error("Details: \(details)")
				do {
					let outcome = try await openId4Vp.dispatch(error: error, details: details)
					if case .rejected = outcome { logger.warning("Verifier rejected error response") }
				} catch { logger.error("Failed to dispatch error response: \(error.localizedDescription)") }
			}
			throw WalletError(description: "OpenID4VP request error: \(readerCertificateValidationMessage ?? error.errorDescription ?? error.localizedDescription)", code: readerCertificateValidationMessage != nil ? .trustError : Self.walletErrorCode(error), innerError: error)
		case let .jwt(request: rrd, warnings):
			self.wrpVerifierWarnings = await wrpRegistrationValidator.wrpVpWarnings
			if !warnings.isEmpty { logger.warning("Policy warnings: \(warnings.mapValues{$0.map(\.violation)})") }
			switch rrd.client {
			case .x509SanDns(_, let certificate), .x509Hash(_, let certificate):
				guard readerAuthValidated, let leaf = certificateChain?.first,
					let validatedCertificate = try? X509.Certificate(derEncoded: [UInt8](leaf)),
					validatedCertificate == certificate else {
					let message = "Required reader certificate authentication was not established"
					readerCertificateValidationMessage = message
					throw WalletError(description: message, code: .trustError)
				}
			case .preRegistered: break // The selected registered key has verified the JAR.
			default: throw WalletError(description: "Unsupported authenticated client", code: .notSecuredRequest)
			}
			let requests = try await handleRequest(rrd)
			readerAuthenticationStatus = .authenticated
			return requests
		}
	}

	static func walletErrorCode(_ error: AuthorizationRequestError) -> WalletError.Code {
		WalletError.Code(rawValue: AuthorizationRequestErrorCode.fromError(error).rawValue) ?? .invalidQueryResolution
	}

	private func handleRequest(_ rrd: ResolvedRequestData) async throws -> [UserRequestInfo] {
		do { return try await handleRequestData(rrd) }
		catch {
			let walletError = error as? WalletError
			let protocolError: ValidationError
			switch walletError?.code {
			case .invalidTransactionData: protocolError = .invalidTransactionData(error.localizedDescription)
			case .credentialNotFound, .claimNotFound, .claimValueMismatch, .claimSetNotSatisfied, .credentialSetNotSatisfied, .dcqlQueryNotSatisfied, .noDocumentsAvailable:
				protocolError = .negativeConsent
			default: protocolError = .invalidRequest
			}
			await dispatchRequestError(protocolError, resolved: rrd)
			throw error
		}
	}

	private func dispatchRequestError(_ error: AuthorizationRequestError, resolved: ResolvedRequestData) async {
		let request = resolved.request
		let details = ErrorDispatchDetails(responseMode: request.responseMode, nonce: request.nonce,
			state: request.state, clientId: resolved.client.id, responseEncryptionSpecification: request.responseEncryptionSpecification)
		do { _ = try await openId4Vp.dispatch(error: error, details: details) }
		catch { logger.error("Failed to dispatch error response: \(error.localizedDescription)") }
	}

	private func handleRequestData(_ rrd: ResolvedRequestData) async throws -> [UserRequestInfo] {
		wrpVerifierPolicy = await wrpRegistrationValidator.wrpVpRegistrationPolicy
		self.resolvedRequestData = rrd
		let vp = rrd.request
		var jwkThumbprint: Data?  = nil
		if let key = vp.clientMetaData?.jwkSet?.keys.first(where: { $0.use == "enc"}),
			let x = key.x, let xd = Data(base64URLEncoded: x), let y = key.y, let yd = Data(base64URLEncoded: y),
			let crv = key.crv, let crvType = MdocDataModel18013.CoseEcCurve(crvName: crv), let ecCrvType = ECCurveType(rawValue: crv) {
			eReaderPub = CoseKey(x: [UInt8](xd), y: [UInt8](yd), crv: crvType)
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
			TransactionLogUtils.withRequest(TransactionLogUtils.parseRequestedClaims(dcql, queryable: dcqlQueryable ?? decodeDocuments()), policy: wrpVerifierPolicy,
				name: TransactionLogUtils.verifierName(legalName: rrd.legalName, certificateSubject: readerCertificateIssuer), identifier: resolvedClientId, transactionalData: try transactionData.map { try TransactionalData(content: $0.map { try $0.decode() }) }, transactionLog: &transactionLog)
			await persistTransactionLog()
			let deviceRequestBytes = try? JSONEncoder().encode(dcql)
			let (fmtsReq, imap, zkSpecMap) = try OpenId4VpUtils.parseDcqlFormats(dcql, idsToDocTypes: transferInfo.idsToDocTypes, logger: logger)
			formatsRequested = fmtsReq; inputDescriptorMap = imap; zkSpecsRequested = zkSpecMap
			dcqlQueryable = decodeDocuments()
			parsedTransactionData = try (transactionData ?? []).map { try PresentationTransactionData(encodedValue: $0.value) }
			let mdocKeyAuthorizations = (docsCbor ?? [:]).compactMapValues { $0.issuerAuth.mso.deviceKeyInfo.keyAuthorizations }
			let eligibleIds = Set(transferInfo.documentObjects.compactMap { id, data -> String? in
				guard transferInfo.privateKeyObjects[id] != nil else { return nil }
				if transferInfo.dataFormats[id] == .cbor { return mdocKeyAuthorizations[id] != nil ? id : nil }
				guard transferInfo.dataFormats[id] == .sdjwt,
					let keys = try? SdJwtUtils.parseCnfBindingKeys(fromDocumentData: data), !keys.isEmpty else { return nil }
				return id
			})
			// Check referenced credentials separately so their absence is invalid_transaction_data,
			// even when DCQL resolution would otherwise return a general access-denied error.
			for transaction in parsedTransactionData {
				var available = false
				for query in dcql.credentials where transaction.credentialIds.contains(query.id.value) {
					try requireQes(query.requireCryptographicHolderBinding != false, "Transaction data requires holder binding")
					let format = query.dataFormat
					guard let docType = query.docTypeOrVct else { continue }
					for id in dcqlQueryable.getCredentials(docOrVctType: docType, docDataFormat: format) where eligibleIds.contains(id) &&
						TransactionDataProcessor.canAuthorize(transaction, documentId: id, mdocKeyAuthorizations: mdocKeyAuthorizations, supportedTypes: openID4VpConfig.supportedTransactionDataTypes) {
						if (try? OpenId4VpUtils.resolveClaimsForCredential(credQuery: query, credId: id, queryable: dcqlQueryable)) != nil { available = true }
					}
				}
				try requireQes(available, "No referenced credential can authorize transaction data")
			}
			var credentialSelectionSets = try OpenId4VpUtils.resolveDcql(
				dcql, queryable: dcqlQueryable, docTypeDisplayNames: docTypeDisplayNames)
			transactionAssignments = [:]; transactionDataByRequest = [:]
			if !parsedTransactionData.isEmpty {
				var validOptions: CredentialSelectionSetOptions = [:]
				for (name, selections) in credentialSelectionSets {
					guard let assignments = try? TransactionDataProcessor.assign(parsedTransactionData, selections: selections,
						eligibleDocumentIds: eligibleIds, mdocKeyAuthorizations: mdocKeyAuthorizations, supportedTypes: openID4VpConfig.supportedTransactionDataTypes) else { continue }
					validOptions[name] = selections
					transactionAssignments[name] = assignments
					transactionDataByRequest[name] = Dictionary(grouping: assignments, by: \.documentId).mapValues { $0.map(\.transaction) }
				}
				try requireQes(!validOptions.isEmpty, "No presentation option can authorize all transaction data")
				credentialSelectionSets = validOptions
			}
			credentialSelections = credentialSelectionSets
			let requestItemsArray = OpenId4VpUtils.getRequestItems(credentialSelectionSets, idsToDocTypes: transferInfo.idsToDocTypes, formatsRequested: formatsRequested)
			let verifierInfoRequestedArray = verifierInfo != nil
				? OpenId4VpUtils.getVerifierInfoRequested(credentialSelectionSets, verifierInfoList: verifierInfo!) : nil
			let certificateIssuerName = readerCertificateIssuer.map(MdocHelpers.getCN(from:))
			let rar = ReaderAuthenticationResult(isValidated: readerAuthValidated, certificateIssuer: certificateIssuerName, validationMessage: readerCertificateValidationMessage, legalName: rrd.legalName, authBytes: nil, certificateChain: certificateChain)
			var results = [UserRequestInfo]()
			for (requestName, requestItems) in requestItemsArray {
				let verifierInfoRequested = verifierInfoRequestedArray?.first(where: { $0.0 == requestName })
				//guard let requestItems, let formatsRequested else { throw WalletError(description: "Invalid request query") }
				var result = UserRequestInfo(
					docDataFormats: formatsRequested,
					itemsRequested: requestItems,
					deviceRequestBytes: deviceRequestBytes,
					verifierInfo: verifierInfoRequested?.1,
					requestName: requestName
				)
				logger.info("Verifier requested items: \(requestItems.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
				result.readerAuthResults = ["": rar]
				results.append(result)
			}
			return results
		} else { throw WalletError(description: "Unsupported presentation query", code: .invalidQueryResolution) }
	}

	fileprivate func makeCborDocs() {
		docsCbor = transferInfo.documentObjects.filter { k,v in Self.filterFormat(transferInfo.dataFormats[k]!, fmt: .cbor)} .mapValues { try? IssuerSigned(data: $0.bytes) }.compactMapValues { $0 }
	}

	func generateCborVpToken(itemsToSend: RequestItems, deviceNameSpacesToSend: RequestDeviceNameSpaces?, transactionDataByDocument: [String: [PresentationTransactionData]] = [:], authenticationContext: ThreadSafeAuthContext) async throws -> (VerifiablePresentation, Data, [Data?], [String], [ClaimInfo], Bool) {
		let docMetadata = transferInfo.docMetadata
		let privateKeyObjects = transferInfo.privateKeyObjects
		let zkSystemRepository = transferInfo.zkSystemRepository
		var deviceNamespaces = deviceNameSpacesToSend ?? [:]
		var requiredBindings: [String: DeviceNameSpaces] = [:]
		for (id, transactions) in transactionDataByDocument where !transactions.isEmpty {
			guard itemsToSend[id] != nil, let document = docsCbor[id], privateKeyObjects[id] != nil else {
				throw WalletError(description: "Missing mdoc credential for transaction data", code: .invalidTransactionData)
			}
			let namespaces = try MdocTransactionData.deviceNameSpaces(transactions,
				keyAuthorizations: document.issuerAuth.mso.deviceKeyInfo.keyAuthorizations,
				supportedTypes: openID4VpConfig.supportedTransactionDataTypes, merging: deviceNamespaces[id])
			deviceNamespaces[id] = namespaces
			requiredBindings[id] = namespaces
		}
		let resp = try await MdocHelpers.getDeviceResponseToSend(
			deviceRequest: nil,
			issuerSigned: docsCbor,
			docMetadata: docMetadata,
			selectedItems: itemsToSend,
			eReaderKey: eReaderPub,
			privateKeyObjects: privateKeyObjects,
			sessionTranscript: sessionTranscript,
			dauthMethod: .deviceSignature,
			signatureAlgorithm: deviceAlgorithm,
			unlockData: unlockData,
			zkSpecsRequested: zkSpecsRequested,
			zkSystemRepository: zkSystemRepository,
			deviceNameSpacesRequested: deviceNamespaces,
			authenticationContext: authenticationContext)
		guard let resp else { throw WalletError(description: "DOCUMENT_ERROR", code: requiredBindings.isEmpty ? .internalError : .invalidTransactionData) }
		for (id, expected) in requiredBindings {
			try MdocTransactionData.validateResponse(resp.deviceResponse, docType: docsCbor[id]!.issuerAuth.mso.docType, expected: expected)
		}
		let sentIds = Set(resp.documentIds + resp.zkpDocumentIds)
		let missingClaims = resp.errorRequestItems.values.contains { $0.values.contains { !$0.isEmpty } }
		let complete = sentIds == Set(itemsToSend.keys) && !missingClaims
		let vpTokenData = Data(resp.deviceResponse.toCBOR(options: CBOROptions()).encode())
		let vpTokenStr = vpTokenData.base64URLEncodedString()
		let claims = TransactionLogUtils.parseCborClaims(resp.validRequestItems)
		return (VerifiablePresentation.generic(vpTokenStr), vpTokenData, resp.responseMetadata, resp.zkpDocumentIds, claims, complete)
	}

	func decodeDocuments() -> DefaultDcqlQueryable {
		if formatsRequested == nil {
			// Derive formatsRequested from existing document data when not yet set (e.g. early policy validation)
			var fmts = [DocType: DocDataFormat]()
			for (docId, docType) in transferInfo.idsToDocTypes {
				if let fmt = transferInfo.dataFormats[docId] { fmts[docType] = fmt }
			}
			formatsRequested = fmts
		}
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
		let defaultDcqlQueryable = DefaultDcqlQueryable(credentials: credentialMap, claimPaths: claimPaths, claimValues: claimValues)
		return defaultDcqlQueryable
	}

	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	///   - deviceNameSpacesToSend: Optional device-signed namespaces to include in the response
	///   - onSuccess: Callback invoked on successful response with an optional redirect URL
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, deviceNameSpacesToSend: RequestDeviceNameSpaces? = nil, authenticationContext: ThreadSafeAuthContext, onSuccess: ((URL?) -> Void)?) async throws {
		try await sendResponse(userAccepted: userAccepted, itemsToSend: itemsToSend, deviceNameSpacesToSend: deviceNameSpacesToSend,
			authenticationContext: authenticationContext, requestName: nil, onSuccess: onSuccess)
	}

	/// Sends the chosen consent option, preserving its credential-query and transaction assignments.
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, deviceNameSpacesToSend: RequestDeviceNameSpaces? = nil,
		authenticationContext: ThreadSafeAuthContext, requestName: String?, onSuccess: ((URL?) -> Void)?) async throws {
		try beginRequestOperation()
		defer { endRequestOperation() }
		presentedDocumentIds = []
		guard readerAuthenticationStatus == .authenticated || readerAuthenticationStatus == .notApplicable else {
			throw WalletError(description: "No successfully validated presentation request", code: .notSecuredRequest)
		}
		guard dcql != nil, let resolved = resolvedRequestData else {
			throw WalletError(description: "Unexpected error", code: .internalError)
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpTokens(nil, dcql, resolved, onSuccess)
			return
		}
		let options = credentialSelections.filter { (requestName == nil || $0.key == requestName) && Set($0.value.map(\.credentialId)) == Set(itemsToSend.keys) }
		let selectedOption = options.first(where: { _ in true })
		let assignments = selectedOption.flatMap { transactionAssignments[$0.key] } ?? []
		let assignmentVariants = Set(options.map { option in
			(transactionAssignments[option.key] ?? []).map { "\($0.documentId):\($0.queryId):\($0.transaction.encodedValue)" }
		})
		if !parsedTransactionData.isEmpty && (assignments.count != parsedTransactionData.count || assignmentVariants.count > 1) {
			let error = ValidationError.invalidTransactionData("Selected credentials cannot authorize all transaction data")
			await dispatchRequestError(error, resolved: resolved)
			throw WalletError(description: error.localizedDescription, code: .invalidTransactionData, innerError: error)
		}
		zkpDocumentIds = [String]()
		logger.info("Openid4vp request items: \(itemsToSend.mapValues { $0.mapValues { ar in ar.map(\.elementIdentifier) } })")
		if unlockData == nil { _ = try await startQrEngagement(secureAreaName: nil, keyOptions: KeyOptions(curve: .P256)) }
		// tuples of inputDescriptor-id, docId and verifiable presentation
		// the inputDescriptor-id is used to identify the input descriptor in the presentation submission
		var inputToPresentations = [(String, String?, VerifiablePresentation)]()
		var presentedClaims = [ClaimInfo]()
		var preparedIds = [String]()
		var allSelectedClaimsPresented = true
		// support sd-jwt documents
		for (docId, nsItems) in itemsToSend {
			guard let docType = transferInfo.idsToDocTypes[docId] else { continue }
			let queryIds = selectedOption?.value.first(where: { $0.credentialId == docId })?.queryIds.map(\.value)
				?? inputDescriptorMap[docType].map { [$0] } ?? []
			for inputDescrId in queryIds {
				let assignedTransactions = assignments.filter { $0.documentId == docId && $0.queryId == inputDescrId }.map(\.transaction)
				if transferInfo.dataFormats[docId] == .cbor {
					if docsCbor == nil { makeCborDocs() }
					let itemsToSend1 = Dictionary(uniqueKeysWithValues: [(docId, nsItems)])
					let vpToken: (VerifiablePresentation, Data, [Data?], [String], [ClaimInfo], Bool)
					do {
						vpToken = try await generateCborVpToken(itemsToSend: itemsToSend1, deviceNameSpacesToSend: deviceNameSpacesToSend,
							transactionDataByDocument: [docId: assignedTransactions], authenticationContext: authenticationContext)
					} catch let error as WalletError where error.code == .invalidTransactionData {
						await dispatchRequestError(ValidationError.invalidTransactionData(error.localizedDescription), resolved: resolved)
						throw error
					}
					zkpDocumentIds!.append(contentsOf: vpToken.3)
					presentedClaims.append(contentsOf: vpToken.4)
					allSelectedClaimsPresented = allSelectedClaimsPresented && vpToken.5
					if !vpToken.4.isEmpty { preparedIds.append(docId) }
					inputToPresentations.append((inputDescrId, docId, vpToken.0))
				} else if transferInfo.dataFormats[docId] == .sdjwt {
					let docSigned = docsSdJwt[docId]; let dpk = transferInfo.privateKeyObjects[docId]
					let docData = transferInfo.documentObjects[docId]
					guard let docSigned, let docData, let dpk, let items = nsItems.first?.value else { continue }
					guard let holderPublicJwk = try SdJwtUtils.parseCnfBindingKeys(fromDocumentData: docData).first else { continue }
					let unlockData = try await dpk.secureArea.unlockKey(id: docId)
					let keyInfo = try await dpk.secureArea.getKeyBatchInfo(id: docId)
					let keyInfoCrv = keyInfo.keyOptions?.curve ?? .P256
					let dsa = keyInfoCrv.defaultSigningAlgorithm
					let signer = try SecureAreaSigner(secureArea: dpk.secureArea, id: docId, index: dpk.index, publicKey: holderPublicJwk, curve: keyInfoCrv, ecAlgorithm: dsa, unlockData: unlockData, context: authenticationContext)
					let signAlg = try SecureAreaSigner.getSigningAlgorithm(dsa)
					let hai = HashingAlgorithmIdentifier(rawValue: transferInfo.hashingAlgs[docId] ?? "") ?? .SHA3256
					guard let presented = try await OpenId4VpUtils.getSdJwtPresentation(docSigned, hashingAlg: hai.hashingAlgorithm(), signer: signer, signAlg: signAlg, requestItems: items, nonce: vpNonce, aud: vpClientId, transactionData: assignedTransactions, supportedTransactionDataTypes: openID4VpConfig.supportedTransactionDataTypes) else {
						continue
					}
					let disclosedPaths = try presented.recreateClaims().disclosuresPerClaimPath ?? [:]
					let allClaimsPresent = items.allSatisfy { item in disclosedPaths.keys.contains { path in item.claimPath.contains2(path) } }
					allSelectedClaimsPresented = allSelectedClaimsPresented && allClaimsPresent
					presentedClaims.append(contentsOf: try TransactionLogUtils.parsePresentedClaims(presented, docType: docType))
					preparedIds.append(docId)
					inputToPresentations.append((inputDescrId, docId, VerifiablePresentation.generic(presented.serialisation)))
				}
			}
		}
		if assignments.contains(where: { assignment in
			!inputToPresentations.contains { $0.0 == assignment.queryId && $0.1 == assignment.documentId }
		}) {
			let error = ValidationError.invalidTransactionData("Unable to bind all authorized transaction data")
			await dispatchRequestError(error, resolved: resolved)
			throw WalletError(description: error.localizedDescription, code: .invalidTransactionData, innerError: error)
		}
		let selectedIds = Set(itemsToSend.keys)
		let bAllPresented = !selectedIds.isEmpty && Set(preparedIds) == selectedIds && allSelectedClaimsPresented
		if !bAllPresented { logger.warning("Not all selected credentials or claims were presented") }
		try await SendVpTokens(inputToPresentations, dcql, resolved, onSuccess,
			presentedClaims: TransactionLogUtils.mergeClaims(presentedClaims), preparedIds: Array(Set(preparedIds)).sorted())
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
	fileprivate func SendVpTokens(_ vpTokens: [(String, String?, VerifiablePresentation)]?, _ dcql: DCQL?, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?, presentedClaims: [ClaimInfo] = [], preparedIds: [String] = []) async throws {
		let consent: ClientConsent = if let vpTokens, dcql != nil {
			// Group by DCQL query id -> array of VPs
			.vpToken(vpContent: .dcql(verifiablePresentations: Dictionary(grouping: vpTokens, by: { try! QueryId(value: $0.0) }).mapValues { $0.map { $0.2 } } ))
		} else { .negative(message: "access_denied") }
		// Generate a direct post authorisation response, applying wallet-preferred response mode if configured
		let response = try buildAuthorizationResponse(resolved: resolved, consent: consent)
		let result: DispatchOutcome = try await openId4Vp.dispatch(response: response)
		switch result {
		case .accepted(let url):
			if case .negative(let message) = consent {
				TransactionLogUtils.withResult(.notCompleted, reason: message, presented: [], transactionLog: &transactionLog)
			} else {
				presentedDocumentIds = preparedIds
				TransactionLogUtils.withResult(.completed, reason: nil, presented: presentedClaims, transactionLog: &transactionLog)
			}
			await persistTransactionLog()
			onSuccess?(url)
		case .rejected(let redirectURI):
			presentedDocumentIds = preparedIds
			TransactionLogUtils.withResult(.notCompleted, reason: "Rejected", presented: presentedClaims, transactionLog: &transactionLog)
			await persistTransactionLog()
			if let redirectURI { onSuccess?(redirectURI) }
			else { throw WalletError(description: "Dispatch rejected", code: .internalError) }
		}
	}

	lazy var chainVerifier: CertificateTrust = { [weak self] certificates async -> Bool in
		guard let self else { return false }
		self.readerAuthValidated = false
		self.readerCertificateIssuer = nil
		self.certificateChain = nil
		self.readerCertificateValidationMessage = "The reader certificate chain is malformed"
		let b64certs = certificates; let certsData = b64certs.compactMap { Data(base64Encoded: $0) }
		guard certsData.count > 0, certsData.count == b64certs.count else { return false }
		// x5c is leaf-first. The leaf identifies the verifier; the last certificate is normally a CA.
		guard let x509 = try? X509.Certificate(derEncoded: [UInt8](certsData[0])) else { return false }
		self.readerCertificateIssuer = x509.subject.description
		// Validate the reader access certificate chain against the configured trust anchors (WRPAC context).
		let (isValid, failureReason) = await self.trustConfig.accessTrustManager.validateCertTrustPath(chain: certsData)
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = failureReason ?? (isValid ? nil : "The reader certificate chain is not trusted")
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
			vpConfiguration: try! .init(vpFormatsSupported: .default(), supportedTransactionDataTypes: openID4VpConfig.supportedTransactionDataTypes),
			errorDispatchPolicy: openID4VpConfig.errorDispatchPolicy,
			session: networking,
			responseEncryptionConfiguration: openID4VpConfig.responseEncryptionConfiguration ?? .default(),
			registrationCertificatePolicy: openID4VpConfig.validateRegistrationCertificate ? .default(validator: wrpRegistrationValidator) : nil
		)
		return res
	}

	/// Builds an `AuthorizationResponse` applying the wallet's preferred response mode if configured.
	/// When `preferredResponseMode` is set, overrides the verifier's requested mode while keeping the response URI from the request.
	/// When not set, delegates to the standard `AuthorizationResponse` init (current behavior).
	func buildAuthorizationResponse(resolved: ResolvedRequestData, consent: ClientConsent) throws -> AuthorizationResponse {
		let request = resolved.request
		// Negative consent: build directly so that missing state (optional in OpenID4VP) does not throw
		if case .negative(let error) = consent {
			let payload = AuthorizationResponsePayload.noConsensusResponseData(state: request.state ?? "", error: error)
			if let preferred = openID4VpConfig.preferredResponseMode {
				let responseURI: URL? = switch request.responseMode {
				case .directPost(let uri): uri
				case .directPostJWT(let uri): uri
				case .query(let uri): uri
				case .fragment(let uri): uri
				case .some(.none), nil: nil
				}
				guard let uri = responseURI else {
					throw WalletError(description: "No response URI for negative consent", code: .internalError)
				}
				switch preferred {
				case .directPost:
					return .directPost(url: uri, data: payload)
				case .directPostJWT:
					guard let spec = request.responseEncryptionSpecification else {
						throw WalletError(description: "directPostJWT requires response encryption specification from verifier", code: .responseEncryptionMissing)
					}
					return .directPostJwt(url: uri, data: payload, responseEncryptionSpecification: spec)
				}
			}
			switch request.responseMode {
			case .directPost(let uri):
				return .directPost(url: uri, data: payload)
			case .directPostJWT(let uri):
				guard let spec = request.responseEncryptionSpecification else {
					throw WalletError(description: "directPostJWT requires response encryption specification from verifier", code: .responseEncryptionMissing)
				}
				return .directPostJwt(url: uri, data: payload, responseEncryptionSpecification: spec)
			default:
				throw WalletError(description: "Unsupported response mode for negative consent", code: .internalError)
			}
		}
		guard let preferred = openID4VpConfig.preferredResponseMode else {
			return try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(), encryptionParameters: .apu(mdocGeneratedNonce.base64urlEncode))
		}
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
		case .negative:
			preconditionFailure("negative consent handled above")
		}
		switch preferred {
		case .directPost:
			return .directPost(url: uri, data: payload)
		case .directPostJWT:
			guard let spec = request.responseEncryptionSpecification else {
				throw WalletError(description: "directPostJWT requires response encryption specification from verifier", code: .responseEncryptionMissing)
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
