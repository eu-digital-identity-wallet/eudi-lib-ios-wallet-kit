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

/// Fault presentation service. Used to communicate error state to the user
public final class FaultPresentationService: @unchecked Sendable, PresentationService {

	public var status: TransferStatus = .error
	public var flow: FlowType = .other
	var error: Error
	public var transactionLog: TransactionLog

	public init(msg: String) {
		self.error = PresentationSession.makeError(str: msg)
		self.transactionLog = TransactionLog(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .failed, errorMessage: msg, type: .presentation, dataFormat: .cbor)
		TransactionLogUtils.setErrorTransactionLog(type: .presentation, error: error, transactionLog: &transactionLog)
	}

	public init(error: Error) {
		self.error = error
		self.transactionLog = TransactionLog(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .failed, type: .presentation, dataFormat: .cbor)
		TransactionLogUtils.setErrorTransactionLog(type: .presentation, error: error, transactionLog: &transactionLog)
	}

	public func startQrEngagement(secureAreaName: String?, crv: CoseEcCurve) async throws -> String {
		throw error
	}

	public func receiveRequest() async throws -> UserRequestInfo {
		throw error
	}

	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems,  onSuccess: ((URL?) -> Void)?) async throws{
		throw error
	}


}
