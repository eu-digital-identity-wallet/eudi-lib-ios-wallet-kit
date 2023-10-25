//
//  File.swift
//  
//
//  Created by ffeli on 23/10/2023.
//
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
import MdocDataModel18013
import MdocDataTransfer18013

class BlePresentationService : PresentationService {
	var bleServerTransfer: MdocGattServer
	var status: TransferStatus = .initializing
	var continuationQrCode: CheckedContinuation<Data?, Error>?
	var continuationRequest: CheckedContinuation<[String: Any], Error>?
	var continuationResponse: CheckedContinuation<Void, Error>?
	var handleSelected: ((Bool, RequestItems?) -> Void)?
	var deviceEngagement: Data?
	var request: [String: Any]?
	var flow: FlowType { .ble }

	public init(parameters: [String: Any]) throws {
		bleServerTransfer = try MdocGattServer(parameters: parameters)
		bleServerTransfer.delegate = self
	}

	public func generateQRCode() async throws -> Data? {
		return try await withCheckedThrowingContinuation { c in
			continuationQrCode = c
			self.bleServerTransfer.performDeviceEngagement()
		}
	}
	
	public func receiveRequest() async throws -> [String: Any] {
		return try await withCheckedThrowingContinuation { c in
			continuationRequest = c
		}
	}
	
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws {
		return try await withCheckedThrowingContinuation { c in
			continuationResponse = c
			handleSelected?(userAccepted, itemsToSend)
			handleSelected = nil
		}
	}

}

extension BlePresentationService: MdocOfflineDelegate {
	public func didChangeStatus(_ newStatus: MdocDataTransfer18013.TransferStatus) {
		status = if let st = TransferStatus(rawValue: newStatus.rawValue) { st } else { .error }
				switch newStatus {
				case .qrEngagementReady:
						if let qrCode = self.bleServerTransfer.qrCodeImageData {
							deviceEngagement = qrCode
							continuationQrCode?.resume(returning: qrCode)
							continuationQrCode = nil
						}
				case .responseSent:
					continuationResponse?.resume(returning: ())
					continuationResponse = nil
		default: break
				}
	}
	
	public func didFinishedWithError(_ error: Error) {
		continuationQrCode?.resume(throwing: error); continuationQrCode = nil
		continuationRequest?.resume(throwing: error); continuationRequest = nil
		continuationResponse?.resume(throwing: error); continuationResponse = nil
	}
	
	public func didReceiveRequest(_ request: [String : Any], handleSelected: @escaping (Bool, MdocDataTransfer18013.RequestItems?) -> Void) {
		self.handleSelected = handleSelected
		self.request = request
		continuationRequest?.resume(returning: request)
		continuationRequest = nil
	}
	
}
