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
import OpenID4VCI

/// Offered issue model contains information gathered by resolving an issue offer URL.
///
/// This information is returned from ``EudiWallet/resolveOfferUrlDocTypes(uriOffer:format:useSecureEnclave:)``
public struct OfferedIssueModel {
	/// Issuer name (currently the URL)
	public let issuerName: String
	/// Document types included in the offer
	public let docModels: [OfferedDocModel]
	/// Transaction code specification (in case of preauthorized flow)
	public let txCodeSpec: TxCode?
	/// Helper var for transaction code requirement
	public var isTxCodeRequired: Bool { txCodeSpec != nil }
}

/// Information about an offered document type
public struct OfferedDocModel {
	/// Document type
	public let docType: String
	/// Display name for document type
	public let displayName: String
}
