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

/// [Doc Types to [Namespace to Items]] dictionary
public typealias RequestItems = [String: [String: [String]]]

/// Presentation service abstract protocol
public protocol PresentationService {
	/// Status of the data transfer
	//var status: TransferStatus { get }
	/// instance of a presentation ``FlowType``
	var flow: FlowType { get }
	/// Generate a QR code to be shown to verifier (optional)
	func startQrEngagement() async throws -> String?
	///
	/// - Returns: The requested items.
	/// Receive request.
	func receiveRequest() async throws -> [String: Any]
	/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces (see ``RequestItems``)
	func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws
}


