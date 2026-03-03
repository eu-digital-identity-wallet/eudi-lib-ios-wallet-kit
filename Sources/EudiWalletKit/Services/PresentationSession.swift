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
*/

import Foundation
import SwiftUI
import Logging
import MdocDataModel18013
import MdocDataTransfer18013
import WalletStorage
import LocalAuthentication

/// Presentation session
///
/// This class wraps the ``PresentationService`` instance, providing bindable fields to a SwifUI view
public final class PresentationSession: @unchecked Sendable, ObservableObject {
	public var presentationService: any PresentationService
	var storageManager: StorageManager!
	var storageService: (any DataStorageService)!
	/// Reader certificate issuer (the Common Name (CN) from the verifier's certificate)
	@Published public var readerCertIssuer: String?
	/// Reader legal name (if provided)
	@Published public var readerLegalName: String?
	/// Reader certificate validation message (only for BLE transfer wih verifier using reader authentication)
	@Published public var readerCertValidationMessage: String?
	/// Reader certificate issuer is valid
	@Published public var readerCertIssuerValid: Bool?
	/// Error message when the ``status`` is in the error state.
	@Published public var uiError: WalletError?
	/// Request items selected by the user to be sent to verifier.
	@Published public var disclosedDocuments: [DocElements] = []
	/// Status of the data transfer.
	@Published public var status: TransferStatus = .initializing
	/// Device engagement data (QR data for the BLE flow)
	@Published public var deviceEngagement: String?
	// map of document id to (doc type, format, display name) pairs
	public var docIdToPresentInfo: [String: DocPresentInfo]!
	// map of document id to key index to use
	public var documentKeyIndexes: [String: Int]!
	/// User authentication required
	var userAuthenticationRequired: Bool
	/// transaction logger
	public var transactionLogger: (any TransactionLogger)?

	public init(presentationService: any PresentationService, storageManager: StorageManager? = nil, storageService: (any DataStorageService)? = nil, docIdToPresentInfo: [String: DocPresentInfo], documentKeyIndexes: [String: Int], userAuthenticationRequired: Bool, transactionLogger: (any TransactionLogger)? = nil) {
		self.presentationService = presentationService
		self.storageManager = storageManager
		self.storageService = storageService
		self.docIdToPresentInfo = docIdToPresentInfo
		self.documentKeyIndexes = documentKeyIndexes
		self.userAuthenticationRequired = userAuthenticationRequired
		self.transactionLogger = transactionLogger
	}

	@MainActor
	/// Decodes a presentation request
	///
	/// The ``disclosedDocuments`` property will be set. Additionally ``readerCertIssuer`` and ``readerCertValidationMessage`` may be set
	/// - Parameter request: Request information
	func decodeRequest(_ request: UserRequestInfo) throws {
		guard docIdToPresentInfo.count > 0 else { throw Self.makeError(str: "No documents added to session ")}
		// show the items as checkboxes
		disclosedDocuments = [DocElements]()
		for (docId, docPresentInfo) in docIdToPresentInfo {
			let docType = docPresentInfo.docType
			let requestFormat = request.docDataFormats[docId] ?? request.docDataFormats[docType]  ?? request.docDataFormats.first(where: { OpenId4VpUtils.vctToDocTypeMatch($0.key, docType)})?.value
			if requestFormat != docPresentInfo.docDataFormat  { continue }
			switch requestFormat {
				case .cbor:
					guard case let .msoMdoc(issuerSigned) = docPresentInfo.typedData else { continue }
					guard let docItemsRequested = request.itemsRequested[docId] ?? request.itemsRequested[docType] else { continue }
					let msoElements = issuerSigned.extractMsoMdocElements(docId: docId, docType: docType, displayName: docPresentInfo.displayName, docClaims: docPresentInfo.docClaims, itemsRequested: docItemsRequested)
					disclosedDocuments.append(.msoMdoc(msoElements))
				case .sdjwt:
					guard case let .sdJwt(signedSdJwt) = docPresentInfo.typedData else { continue }
					guard let sdItemsRequested = request.itemsRequested[docId] ?? request.itemsRequested[docType] else { continue }
					let sdJwtElements = signedSdJwt.extractSdJwtElements(docId: docId, vct: docType, displayName: docPresentInfo.displayName, docClaims: docPresentInfo.docClaims, itemsRequested: sdItemsRequested)
					guard let sdJwtElements else { continue }
					disclosedDocuments.append(.sdJwt(sdJwtElements))
				default: logger.error("Unsupported format \(docPresentInfo.docDataFormat) for \(docId)")
			}

		}
		if let readerAuthority = request.readerCertificateIssuer {
			readerCertIssuer = readerAuthority
			readerCertIssuerValid = request.readerAuthValidated
			readerCertValidationMessage = request.readerCertificateValidationMessage
		}
		readerLegalName = request.readerLegalName
		if disclosedDocuments.count == 0 { throw Self.makeError(str: Self.NotAvailableStr, localizationKey: "request_data_no_document") }
		status = .requestReceived
	}

	static let NotAvailableStr = "The requested document is not available in your EUDI Wallet. Please contact the authorised issuer for further information."

	public static func makeError(str: String, localizationKey: String? = nil) -> WalletError {
		logger.error(Logger.Message(unicodeScalarLiteral: str))
		return WalletError(description: str, localizationKey: localizationKey)
	}

	public static func makeError(err: LocalizedError) -> WalletError {
		logger.error(Logger.Message(unicodeScalarLiteral: err.errorDescription ?? err.localizedDescription))
		return WalletError(description: err.errorDescription ?? err.localizedDescription)
	}

	/// Start QR engagement to be presented to verifier
	///
	/// On success ``deviceEngagement`` published variable will be set with the result and ``status`` will be ``.qrEngagementReady``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	public func startQrEngagement() async throws {
		if docIdToPresentInfo.count == 0 { await setError(Self.NotAvailableStr, localizationKey: "request_data_no_document"); return }
		do {
			let data = try await presentationService.startQrEngagement(secureAreaName: nil, crv: .P256)
			await MainActor.run {
				deviceEngagement = data
				status = .qrEngagementReady
			}
		} catch { await setError(error.localizedDescription) }
	}

	@MainActor
	func setError(_ description: String, localizationKey: String? = nil) {
		status = .error
		uiError = WalletError(description: description, localizationKey: localizationKey)
	}

	/// Receive request from verifer
	///
	/// The request is futher decoded internally. See also ``decodeRequest(_:)``
	/// On success ``disclosedDocuments`` published variable will be set  and ``status`` will be ``.requestReceived``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	/// - Returns: A request object
	public func receiveRequest() async -> UserRequestInfo? {
		do {
			let request = try await presentationService.receiveRequest()
			try await decodeRequest(request)
			return request
		} catch {
			await setError(error.localizedDescription)
			return nil
		}
	}

	func updateKeyBatchInfoAndDeleteCredentialIfNeeded(presentedIds: [String]) async throws {
		for (id, dpi) in docIdToPresentInfo where presentedIds.contains(id) {
			let secureArea = SecureAreaRegistry.shared.get(name: dpi.secureAreaName)
			guard let keyIndex = documentKeyIndexes[id] else { continue }
			let newKeyBatchInfo = try await secureArea.updateKeyBatchInfo(id: id, keyIndex: keyIndex)
			if newKeyBatchInfo.credentialPolicy == .oneTimeUse {
				try await storageService?.deleteDocumentCredential(id: id, index: keyIndex)
				try await secureArea.deleteKeyBatch(id: id, startIndex: keyIndex, batchSize: 1)
				let remaining: Int? = newKeyBatchInfo.usedCounts.count { $0 == 0 }
				let uc = remaining.map { try! CredentialsUsageCounts(total: newKeyBatchInfo.usedCounts.count, remaining: $0) }
				storageManager?.setUsageCount(uc, id: id)
			}
		}
	}

/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: Whether user confirmed to send the response
	///   - itemsToSend: Data to send organized into a hierarchy of doc.types and namespaces
	///   - onCancel: Action to perform if the user cancels the biometric authentication
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onCancel: (() -> Void)? = nil, onSuccess: (@Sendable (URL?) -> Void)? = nil) async throws {
		do {
			await MainActor.run { status = .userSelected }
			let action = { [ weak self] in _ = try await self?.presentationService.sendResponse(userAccepted: userAccepted, itemsToSend: itemsToSend, onSuccess: onSuccess) }
			try await EudiWallet.authorizedAction(action: action, disabled: !userAuthenticationRequired, dismiss: { onCancel?() }, localizedReason: NSLocalizedString("authenticate_to_share_data", comment: "") )
			await MainActor.run { status = .responseSent }
			try await updateKeyBatchInfoAndDeleteCredentialIfNeeded(presentedIds: Array(itemsToSend.keys))
			if let transactionLogger { do { try await transactionLogger.log(transaction: presentationService.transactionLog) } catch { logger.error("Failed to log transaction: \(error)") } }
		} catch {
			await setError(error.localizedDescription)
			let setErrorTransactionLog = presentationService.transactionLog.copy(status: .failed, errorMessage: error.localizedDescription)
			if let transactionLogger { do { try await transactionLogger.log(transaction: setErrorTransactionLog) } catch { logger.error("Failed to log transaction") } }
			throw error
		}
	}



}
