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
import MdocDataTransfer18013

/// Fault presentation service. Used to communicate error state to the user
public class FaultPresentationService: PresentationService {
	public var status: TransferStatus = .error
	public var flow: FlowType = .other
	var error: Error
	
	public init(msg: String) {
		self.error = PresentationSession.makeError(str: msg)
	}
	
	public init(error: Error) {
		self.error = error
	}
	
	public func startQrEngagement() async throws -> String? {
		throw error
	}
	
	public func receiveRequest() async throws -> [String : Any] {
		throw error
	}
	
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems,  onSuccess: ((URL?) -> Void)?) async throws{
		throw error
	}
	
	
}
