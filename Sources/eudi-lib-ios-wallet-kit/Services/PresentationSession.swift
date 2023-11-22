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
@_exported import MdocDataTransfer18013
import LocalAuthentication

/// Presentation session
///
/// This class wraps the ``PresentationService`` instance, providing bindable fields to a SwifUI view
public class PresentationSession: ObservableObject {
	public var presentationService: any PresentationService
	/// Reader certificate issuer (only for BLE flow wih verifier using reader authentication)
	@Published public var readerCertIssuer: String?
	/// Reader certificate validation message (only for BLE transfer wih verifier using reader authentication)
	@Published public var readerCertValidationMessage: String?
	/// Error message when the ``status`` is in the error state.
	@Published public var uiError: WalletError?
	/// Request items selected by the user to be sent to verifier.
	@Published public var disclosedDocuments: [DocElementsViewModel] = []
	/// Status of the data transfer.
	@Published public var status: TransferStatus = .initializing
	/// The ``FlowType`` instance
	public var flow: FlowType { presentationService.flow }
	var handleSelected: ((Bool, RequestItems?) -> Void)?
	/// Device engagement data (QR image data for the BLE flow)
	@Published public var deviceEngagement: Data?
	
	public init(presentationService: any PresentationService) {
		self.presentationService = presentationService
	}
	
	@MainActor
	/// Decodes a presentation request
	///
	/// The ``disclosedDocuments`` property will be set. Additionally ``readerCertIssuer`` and ``readerCertValidationMessage`` may be set for the BLE proximity flow
	/// - Parameter request: Keys are defined in the ``UserRequestKeys``
	public func decodeRequest(_ request: [String: Any]) {
		// show the items as checkboxes
		guard let validRequestItems = request[UserRequestKeys.valid_items_requested.rawValue] as? RequestItems else { return }
		var tmp = validRequestItems.toDocElementViewModels(valid: true)
		if let errorRequestItems = request[UserRequestKeys.error_items_requested.rawValue] as? RequestItems, errorRequestItems.count > 0 {
			tmp = tmp.merging(with: errorRequestItems.toDocElementViewModels(valid: false))
		}
		disclosedDocuments = tmp
		if let readerAuthority = request[UserRequestKeys.reader_certificate_issuer.rawValue] as? String {
			readerCertIssuer = readerAuthority
			readerCertValidationMessage = request[UserRequestKeys.reader_certificate_validation_message.rawValue] as? String ?? ""
		}
	}
	
	static func makeError(str: String) -> NSError {
		logger.error(Logger.Message(unicodeScalarLiteral: str))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: str])
	}
	
	@MainActor
	/// Start QR engagement to be presented to verifier
	///
	/// On success ``deviceEngagement`` published variable will be set with the result and ``status`` will be ``.qrEngagementReady``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	public func startQrEngagement() async {
		do {
			let data = try await presentationService.startQrEngagement()
			if let data, data.count > 0 {
				deviceEngagement = data
				status = .qrEngagementReady
			}
		} catch {
			status = .error
			uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code, userInfo: (error as NSError).userInfo)
		}
	}
	
	@MainActor
	/// Receive request from verifer
	///
	/// The request is futher decoded internally. See also ``decodeRequest(_:)``
	/// On success ``disclosedDocuments`` published variable will be set  and ``status`` will be ``.requestReceived``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	/// - Returns: A request dictionary keyed by ``MdocDataTransfer.UserRequestKeys``
	public func receiveRequest() async -> [String: Any]? {
		do {
			let request = try await presentationService.receiveRequest()
			decodeRequest(request)
			status = .requestReceived
			return request
		} catch {
			uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code, userInfo: (error as NSError).userInfo)
			status = .error
			return nil
		}
	}
	
	@MainActor
	/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: Whether user confirmed to send the response
	///   - itemsToSend: Data to send organized into a hierarcy of doc.types and namespaces
	///   - onCancel: Action to perform if the user cancels the biometric authentication
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onCancel: (() -> Void)?) async {
		do {
			status = .userSelected
			let action = { [ weak self] in _ = try await self?.presentationService.sendResponse(userAccepted: userAccepted, itemsToSend: itemsToSend) }
			if EudiWallet.standard.userAuthenticationRequired {
				try await EudiWallet.authorizedAction(dismiss: { onCancel?()}, action: action )
			} else {
				try await action()
			}
			status = .responseSent
		} catch {
			status = .error
			uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code, userInfo: (error as NSError).userInfo)
		}
	}
	
	

}
