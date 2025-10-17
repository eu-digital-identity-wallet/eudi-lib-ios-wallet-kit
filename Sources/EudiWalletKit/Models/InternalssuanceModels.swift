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
import WalletStorage

struct CredentialConfiguration: Codable, Sendable {
	/// the credential issuer identifier (issuer URL)
	let configurationIdentifier: CredentialConfigurationIdentifier
	let credentialIssuerIdentifier: String
    let docType: String?
	let vct: String?
    let scope: String?
    let credentialSigningAlgValuesSupported: [String]
	let issuerDisplay: [DisplayMetadata]    //public let proofTypesSupported: [String: ProofTypeSupportedMeta]?
    let display: [DisplayMetadata]
    let claims: [Claim]
   	let format: DocDataFormat
	var batchSize: Int?
	let defaultCredentialOptions: CredentialOptions

	public init(configurationIdentifier: CredentialConfigurationIdentifier, credentialIssuerIdentifier: String, docType: String? = nil, vct: String? = nil, scope: String? = nil, credentialSigningAlgValuesSupported: [String], issuerDisplay: [DisplayMetadata], display: [DisplayMetadata], claims: [Claim], format: DocDataFormat, defaultCredentialOptions: CredentialOptions) {
		self.configurationIdentifier = configurationIdentifier
		self.credentialIssuerIdentifier = credentialIssuerIdentifier
		self.docType = docType
		self.vct = vct
		self.scope = scope
		self.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
		self.issuerDisplay = issuerDisplay
		self.display = display
		self.claims = claims
		self.format = format
		self.defaultCredentialOptions = defaultCredentialOptions
	}
 }

struct DeferredIssuanceModel: Codable, Sendable {
	let deferredCredentialEndpoint: CredentialIssuerEndpoint
	let accessToken: IssuanceAccessToken
	let refreshToken: IssuanceRefreshToken?
	let transactionId: TransactionId
	let publicKeys: [Data]
	let derKeyData: Data?
	let configuration: CredentialConfiguration
	let timeStamp: TimeInterval
}

struct PendingIssuanceModel: Codable {
	// pending reason
	enum PendingReason: Codable {
		case presentation_request_url(String)
	}
	let pendingReason: PendingReason
	let configuration: CredentialConfiguration
	let metadataKey: String
	let pckeCodeVerifier: String
	let pckeCodeVerifierMethod: String
}

enum IssuanceOutcome {
	case issued([(data: Data, pk: Data)], CredentialConfiguration)
	case deferred(DeferredIssuanceModel)
	case pending(PendingIssuanceModel)
}

extension IssuanceOutcome {
	var isDeferred: Bool {
		switch self {
		case .deferred(_): true
		default: false
		}
	}
	var isPending: Bool {
		switch self {
		case .pending(_): true
		default: false
		}
	}
	var pendingOrDeferredStatus: DocumentStatus? {
		switch self {
		case .deferred(_): .deferred
		case .pending(_): .pending
		default: nil
		}
	}

	func getDataToSave(index: Int, format: DocDataFormat) -> Data {
		guard case let .issued(dataPairs, _) = self, dataPairs.count > index else { return Data() }
		let (data, _) = dataPairs[index]
		return data
	}

	func getPublicKey(index: Int) -> Data {
		guard case let .issued(dataPairs, _) = self, dataPairs.count > index else { return Data() }
		let (_, pk) = dataPairs[index]
		return pk
	}
}

