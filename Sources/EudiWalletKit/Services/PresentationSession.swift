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
import LocalAuthentication

/// Presentation session
///
/// This class wraps the ``PresentationService`` instance, providing bindable fields to a SwifUI view
public final class PresentationSession: @unchecked Sendable, ObservableObject {
	public var presentationService: any PresentationService
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
	@Published public var disclosedDocuments: [DocElementsViewModel] = []
	/// Status of the data transfer.
	@Published public var status: TransferStatus = .initializing
	/// The ``FlowType`` instance
	// public var flow: FlowType { presentationService.flow }
	var handleSelected: ((Bool, RequestItems?) -> Void)?
	/// Device engagement data (QR data for the BLE flow)
	@Published public var deviceEngagement: String?
	// map of document id to (doc type, format, display name) pairs
	public var docIdAndTypes: [String: (String, DocDataFormat, String?)]
	/// User authentication required
	var userAuthenticationRequired: Bool
	
	public init(presentationService: any PresentationService, docIdAndTypes: [String: (String, DocDataFormat, String?)], userAuthenticationRequired: Bool) {
		self.presentationService = presentationService
		self.docIdAndTypes = docIdAndTypes
		self.userAuthenticationRequired = userAuthenticationRequired
	}
	
	@MainActor
	/// Decodes a presentation request
	///
	/// The ``disclosedDocuments`` property will be set. Additionally ``readerCertIssuer`` and ``readerCertValidationMessage`` may be set
	/// - Parameter request: Request information
	func decodeRequest(_ request: UserRequestInfo) throws {
		guard docIdAndTypes.count > 0 else { throw Self.makeError(str: "No documents added to session ")}
		// show the items as checkboxes
		disclosedDocuments = [DocElementsViewModel]()
		for (docId, (docType, docDataFormat, displayName)) in docIdAndTypes {
			let requestFormat = request.docDataFormats[docId] ?? request.docDataFormats[docType]  ?? request.docDataFormats.first(where: { Openid4VpUtils.vctToDocTypeMatch($0.key, docType)})?.value
			if requestFormat != docDataFormat  { continue }
			var tmp = request.validItemsRequested.toDocElementViewModels(docId: docId, docType: docType, displayName: displayName, valid: true)
			if let errorRequestItems = request.errorItemsRequested, errorRequestItems.count > 0 {
				tmp = tmp.merging(with: errorRequestItems.toDocElementViewModels(docId: docId, docType: docType, displayName: displayName, valid: false))
			}
			disclosedDocuments.append(contentsOf: tmp)
		}
		if let readerAuthority = request.readerCertificateIssuer {
			readerCertIssuer = readerAuthority
			readerCertIssuerValid = request.readerAuthValidated
			readerCertValidationMessage = request.readerCertificateValidationMessage
		}
		readerLegalName = request.readerLegalName 
		status = .requestReceived
	}
	
	public static func makeError(str: String) -> NSError {
		logger.error(Logger.Message(unicodeScalarLiteral: str))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: str])
	}
	
	public static func makeError(code: MdocDataTransfer18013.ErrorCode, str: String? = nil) -> NSError {
		let message = str ?? code.description
		logger.error(Logger.Message(unicodeScalarLiteral: message))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: message])
	}
	
	/// Start QR engagement to be presented to verifier
	///
	/// On success ``deviceEngagement`` published variable will be set with the result and ``status`` will be ``.qrEngagementReady``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	public func startQrEngagement() async {
		do {
			let data = try await presentationService.startQrEngagement(secureAreaName: nil, crv: .P256)
			await MainActor.run {
				deviceEngagement = data
				status = .qrEngagementReady
			}
		} catch { await setError(error) }
	}
	
	@MainActor
	func setError(_ error: Error) {
		status = .error
		uiError = WalletError(description: error.localizedDescription, userInfo: (error as NSError).userInfo)
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
			await setError(error)
			return nil
		}
	}
	
	/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: Whether user confirmed to send the response
	///   - itemsToSend: Data to send organized into a hierarcy of doc.types and namespaces
	///   - onCancel: Action to perform if the user cancels the biometric authentication
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onCancel: (() -> Void)? = nil, onSuccess: (@Sendable (URL?) -> Void)? = nil) async {
		do {
			await MainActor.run {status = .userSelected }
			let action = { [ weak self] in _ = try await self?.presentationService.sendResponse(userAccepted: userAccepted, itemsToSend: itemsToSend, onSuccess: onSuccess) }
			try await EudiWallet.authorizedAction(action: action, disabled: !userAuthenticationRequired, dismiss: { onCancel?()}, localizedReason: NSLocalizedString("authenticate_to_share_data", comment: "") )
			await MainActor.run {status = .responseSent }
		} catch { await setError(error) }
	}
	
	

}
