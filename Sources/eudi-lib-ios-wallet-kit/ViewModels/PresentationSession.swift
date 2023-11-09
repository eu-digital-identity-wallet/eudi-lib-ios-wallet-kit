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
	var presentationService: any PresentationService
	/// Reader certificate issuer (only for BLE flow wih verifier using reader authentication)
	@Published public var readerCertIssuerMessage: String?
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
			//let bAuthenticated = request[UserRequestKeys.reader_auth_validated.rawValue] as? Bool ?? false
			readerCertIssuerMessage = "Reader Certificate Issuer:\n\(readerAuthority)"
			readerCertValidationMessage = request[UserRequestKeys.reader_certificate_validation_message.rawValue] as? String ?? ""
		}
	}

	public func didFinishedWithError(_ error: Error) {
		uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code)
	}
	
	static func makeError(str: String) -> NSError {
		logger.error(Logger.Message(unicodeScalarLiteral: str))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: str])
	}
	
	public static var notAvailable: PresentationSession { PresentationSession(presentationService: FaultPresentationService(error: Self.makeError(str: "N/A"))) }
}

extension PresentationSession: PresentationService {
	
	@discardableResult @MainActor
	public func startQrEngagement() async throws -> Data? {
		do {
			let data = try await presentationService.startQrEngagement()
			if let data, data.count > 0 {
				deviceEngagement = data
				status = .qrEngagementReady
			}
			return data
		} catch {
			status = .error
			uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code)
			return nil
		}
	}
	
	@discardableResult @MainActor
	public func receiveRequest() async throws -> [String: Any] {
		do {
			let request = try await presentationService.receiveRequest()
			decodeRequest(request)
			status = .requestReceived
			return request
		} catch {
			status = .error
			uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code)
			return [:]
		}
	}
	
	@MainActor
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws {
		do {
			status = .userSelected
			 try await presentationService.sendResponse(userAccepted: userAccepted, itemsToSend: itemsToSend)
			status = .responseSent
		} catch {
			status = .error
			uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code)
		}
	}
	
	

}
