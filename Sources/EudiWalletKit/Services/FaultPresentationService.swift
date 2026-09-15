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
*/

import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import struct WalletStorage.Document

/// Fault presentation service. Used to communicate error state to the user
public final class FaultPresentationService: @unchecked Sendable, PresentationService {
	public var status: TransferStatus = .error
	public var flow: FlowType = .other
	public var zkpDocumentIds: [Document.ID]?
	var error: Error
	public var wrpVerifierPolicy: WrpRegistrationPolicy?
	public var wrpVerifierWarnings: [String: [PresentationPolicyViolation]]?
	public var transactionLogger: (any TransactionLogger)?
	public var transactionLog: TransactionEntry

	public init(msg: String) {
		self.error = WalletError(description: msg, code: .internalError)
		self.transactionLog = TransactionLogUtils.createEmptyPresentationLog()
		TransactionLogUtils.withResult(.notCompleted, reason: error.localizedDescription, transactionLog: &transactionLog)
	}

	public init(error: Error) {
		self.error = error
		self.transactionLog = TransactionLogUtils.createEmptyPresentationLog()
		TransactionLogUtils.withResult(.notCompleted, reason: error.localizedDescription, transactionLog: &transactionLog)
	}

	public func startQrEngagement(secureAreaName: String?, keyOptions: KeyOptions) async throws -> String {
		throw error
	}

	public func receiveRequest() async throws -> [UserRequestInfo] {
		throw error
	}

	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, deviceNameSpacesToSend: RequestDeviceNameSpaces? = nil, authenticationContext: ThreadSafeAuthContext = ThreadSafeAuthContext(), onSuccess: ((URL?) -> Void)?) async throws{
		throw error
	}

	public func waitForDisconnect() async throws {
		throw error
	}
}
