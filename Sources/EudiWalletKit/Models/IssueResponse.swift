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
import WalletStorage
import struct OpenID4VCI.PolicyViolation

/// Result of an OpenID4VCI issuance operation.
///
/// Pairs the issued documents with any warnings produced by the WRP registration
/// certificate (WRPRC) policy when ``OpenId4VciConfiguration/validateRegistrationCertificate``
/// is enabled.
public struct IssueResponse: Sendable {
	/// The issued documents. They are already saved in storage.
	public let documents: [WalletStorage.Document]
	/// Warnings produced by the WRP registration certificate policy, keyed by credential
	/// configuration identifier; the empty key holds request-wide warnings.
	public let wrpRegistrationWarnings: [String: [PolicyViolation]]

	public init(documents: [WalletStorage.Document], wrpRegistrationWarnings: [String: [PolicyViolation]] = [:]) {
		self.documents = documents
		self.wrpRegistrationWarnings = wrpRegistrationWarnings
	}

	/// Registration-policy warnings matched to each issued document, keyed by document identifier.
	///
	/// A document is matched to the warnings of its credential configuration identifier
	/// (taken from the document metadata).
	public var documentWarnings: [WalletStorage.Document.ID: [PolicyViolation]] {
		var result = [WalletStorage.Document.ID: [PolicyViolation]]()
		for document in documents {
			guard let configurationIdentifier = DocMetadata(from: document.metadata)?.configurationIdentifier,
				let warnings = wrpRegistrationWarnings[configurationIdentifier], !warnings.isEmpty else { continue }
			result[document.id] = warnings
		}
		return result
	}
}
