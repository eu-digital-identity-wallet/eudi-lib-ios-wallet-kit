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
/// Wallet error
public struct WalletError: LocalizedError {
	/// Structured error code for programmatic handling
	public enum Code: String, Sendable {
		/// The verifier requested a claim that is not present in the credential
		case claimNotFound
		/// The verifier requested a credential/document type that is not in the wallet
		case credentialNotFound
		/// The verifier requested a claim whose value does not match
		case claimValueMismatch
		/// No claim_set option could be satisfied
		case claimSetNotSatisfied
		/// A required credential_set cannot be satisfied
		case credentialSetNotSatisfied
		/// The DCQL query could not be satisfied (general)
		case dcqlQueryNotSatisfied
		/// Bluetooth is not authorized by the user
		case bleNotAuthorized
		/// Bluetooth is not supported on this device
		case bleNotSupported
		/// No documents available for presentation
		case noDocumentsAvailable
	}

	public let description: String
	/// Deprecated: prefer using `code` for programmatic error handling
	public let localizationKey: String?
	/// Structured error code for programmatic handling. `nil` for legacy errors.
	public let code: Code?
	/// Additional context about the error (e.g. claim path, docType).
	public let context: [String: String]

	public init(description: String, localizationKey: String? = nil, code: Code? = nil, context: [String: String] = [:]) {
		self.description = description
		self.localizationKey = localizationKey
		self.code = code
		self.context = context
	}

	public var errorDescription: String? {
		if let localizationKey = localizationKey {
			return NSLocalizedString(localizationKey, comment: description)
		} else {
			return description
		}
	}

}
