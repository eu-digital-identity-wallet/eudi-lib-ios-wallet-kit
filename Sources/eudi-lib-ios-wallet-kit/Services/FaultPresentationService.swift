 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
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
