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
import MdocDataModel18013

/// [Doc Types to [Namespace to Items]] dictionary
public typealias RequestItems = [String: [String: [String]]]

/// Presentation service abstract protocol
public protocol PresentationService {
	/// Status of the data transfer
	var status: TransferStatus { get }
	/// instance of a presentation ``FlowType``
	var flow: FlowType { get }
	/// Generate a QR code to be shown to verifier (optional)
	func startQrEngagement() async throws -> Data?
	///
	/// - Returns: The requested items.
	/// Receive request.
	func receiveRequest() async throws -> [String: Any]
	/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces (see ``RequestItems``)
	func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
}


