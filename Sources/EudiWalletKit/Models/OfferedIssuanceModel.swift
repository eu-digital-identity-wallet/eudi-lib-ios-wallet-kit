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
import OpenID4VCI
import Copyable

/// Offered issue model contains information gathered by resolving an issue offer URL.
///
/// This information is returned from ``EudiWallet/resolveOfferUrlDocTypes(uriOffer:)``
public struct OfferedIssuanceModel: Sendable {
	/// public initializer
	public init(issuerName: String, issuerLogoUrl: String? = nil, docModels: [OfferedDocModel], txCodeSpec: TxCode? = nil) {
		self.issuerName = issuerName
		self.issuerLogoUrl = issuerLogoUrl
		self.docModels = docModels
		self.txCodeSpec = txCodeSpec
	}
	/// Issuer name
	public let issuerName: String
	/// Issuer logo URL
	public let issuerLogoUrl: String?
	/// Document types included in the offer
	public let docModels: [OfferedDocModel]
	/// Transaction code specification (in case of preauthorized flow)
	public let txCodeSpec: TxCode?
	/// Helper var for transaction code requirement
	public var isTxCodeRequired: Bool { txCodeSpec != nil }
}

/// Information about an offered document to issue
@Copyable
public struct OfferedDocModel: Sendable {
	/// public initializer
	public init(credentialConfigurationIdentifier: String, docType: String? = nil, vct: String? = nil, scope: String, identifier: String?, displayName: String, algValuesSupported: [String], claims: [Claim], credentialOptions: CredentialOptions, keyOptions: KeyOptions?) {
		self.credentialConfigurationIdentifier = credentialConfigurationIdentifier
		self.docType = docType
		self.vct = vct
		self.scope = scope
		self.identifier = identifier
		self.displayName = displayName
		self.algValuesSupported = algValuesSupported
		self.claims = claims
		self.credentialOptions = credentialOptions
		self.keyOptions = keyOptions
	}
	/// Credential configuration identifier from VCI issuer
	public let credentialConfigurationIdentifier: String
	/// Document type
	public let docType: String?
	/// vct (for sdJwt credential offers)
	public let vct: String?
	/// Scope
	public let scope: String
	/// issuer configuration identifier
	public let identifier: String?
	/// Display name for document type
	public let displayName: String
	/// Credential signing algorithm values supported
	public let algValuesSupported: [String]
	/// Doc type or vct
	public var docTypeOrVct: String? {
		docType ?? vct
	}
	// claims supported for the document
	public let claims: [Claim]
	// options for the credential
	public let credentialOptions: CredentialOptions
	// key options
	public let keyOptions: KeyOptions?

	/// Convert OfferedDocModel to DocTypeIdentifier
	public var docTypeIdentifier: DocTypeIdentifier? {
		if let identifier = identifier {
			return .identifier(identifier)
		} else if let docType = docType {
			return .msoMdoc(docType: docType)
		} else if let vct = vct {
			return .sdJwt(vct: vct)
		} else {
			return nil
		}
	}
}

