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
import MdocDataTransfer18013

public class PresentationSession: ObservableObject {
	var presentationService: any PresentationService
	@Published public var readerCertIsserMessage: String?
	@Published public var readerCertValidationMessage: String?
	@Published public var errorMessage: String = ""
	@Published public var selectedRequestItems: [DocElementsViewModel] = []
	@Published public var status: TransferStatus = .initializing
	public var flow: FlowType { presentationService.flow }
	public var handleSelected: ((Bool, RequestItems?) -> Void)?
	@Published public var deviceEngagement: Data? 
	
	public init(presentationService: any PresentationService) {
		self.presentationService = presentationService
	}
	
	@MainActor
	public func decodeRequest(_ request: [String: Any]) {
		// show the items as checkboxes
		guard let validRequestItems = request[UserRequestKeys.valid_items_requested.rawValue] as? RequestItems else { return }
		var tmp = validRequestItems.toDocElementViewModels(valid: true)
		if let errorRequestItems = request[UserRequestKeys.error_items_requested.rawValue] as? RequestItems, errorRequestItems.count > 0 {
			tmp = tmp.merging(with: errorRequestItems.toDocElementViewModels(valid: false))
		}
		selectedRequestItems = tmp
		if let readerAuthority = request[UserRequestKeys.reader_certificate_issuer.rawValue] as? String {
			//let bAuthenticated = request[UserRequestKeys.reader_auth_validated.rawValue] as? Bool ?? false
			readerCertIsserMessage = "Reader Certificate Issuer:\n\(readerAuthority)"
			readerCertValidationMessage = request[UserRequestKeys.reader_certificate_validation_message.rawValue] as? String ?? ""
		}
	}

	public func didFinishedWithError(_ error: Error) {
		errorMessage = error.localizedDescription
	}
	
	public static func makeError(str: String) -> NSError {
		logger.error(Logger.Message(unicodeScalarLiteral: str))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: str])
	}
	
	public static var notAvailable: PresentationSession { PresentationSession(presentationService: FaultPresentationService(error: Self.makeError(str: "N/A"))) }
}

extension PresentationSession: PresentationService {
	
   @MainActor
   @discardableResult	public func presentAttestations() async throws -> [String: Any] {
		deviceEngagement = try await generateQRCode()
		return try await receiveRequest()
	}
	
	@MainActor
	public func generateQRCode() async throws -> Data? {
		do {
			let data = try await presentationService.generateQRCode()
			if let data, data.count > 0 { status = .qrEngagementReady }
			return data
		} catch {
			status = .error
			self.errorMessage = error.localizedDescription
			return nil
		}
	}
	
	@MainActor
	public func receiveRequest() async throws -> [String: Any] {
		do {
			let request = try await presentationService.receiveRequest()
			decodeRequest(request)
			status = .requestReceived
			return request
		} catch {
			status = .error
			self.errorMessage = error.localizedDescription
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
			self.errorMessage = error.localizedDescription
		}
	}
}
