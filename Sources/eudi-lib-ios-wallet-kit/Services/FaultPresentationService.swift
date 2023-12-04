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

/// Fault presentation service. Used to communicate error state to the user
class FaultPresentationService: PresentationService {
	var status: TransferStatus = .error
	var flow: FlowType = .ble
	var error: Error
	
	init(error: Error) {
		self.error = error
	}
	
	func startQrEngagement() async throws -> Data? {
		throw error
	}
	
	func receiveRequest() async throws -> [String : Any] {
		throw error
	}
	
	func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws{
		throw error
	}
	
	
}
