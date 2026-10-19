/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import OpenID4VCI
import Testing
@testable import EudiWalletKit

private struct MissingSignedMetadataFetcher: MetadataFetching {
	func fetchMetadata(
		url: URL,
		policy: IssuerMetadataPolicy,
		issuerId: CredentialIssuerId
	) async -> Result<CredentialIssuerMetadata, CredentialIssuerMetadataError> {
		.failure(.missingSignedMetadata)
	}
}

@Suite("Credential offer error recovery")
struct CredentialOfferErrorRecoveryTests {
	@Test("recovers the concrete issuer metadata error")
	func recoversMetadataError() async {
		let source = CredentialOfferRequest.passByValue(metaData: """
			{
			  "credential_issuer": "https://issuer.example.com",
			  "credential_configuration_ids": ["pid"]
			}
			""")
		let flattened = ValidationError.error(reason: "Invalid credential metadata")
		let resolver = CredentialIssuerMetadataResolver(fetcher: MissingSignedMetadataFetcher())

		let recovered = await source.recoverMetadataError(
			from: flattened,
			policy: .ignoreSigned,
			fetcher: Fetcher<CredentialOfferRequestObject>(),
			metadataResolver: resolver
		)

		guard let metadataError = recovered as? CredentialIssuerMetadataError else {
			Issue.record("Expected CredentialIssuerMetadataError, got \(type(of: recovered))")
			return
		}
		guard case .missingSignedMetadata = metadataError else {
			Issue.record("Expected missingSignedMetadata, got \(metadataError)")
			return
		}
		#expect(CredentialOfferRequest.metadataErrorDescription(for: recovered) == "Credential issuer metadata is not signed")
	}

	@Test("leaves unrelated resolver errors unchanged")
	func preservesUnrelatedError() async {
		let original = ValidationError.error(reason: "Invalid authorization metadata")
		let recovered = await CredentialOfferRequest.passByValue(metaData: "{}").recoverMetadataError(
			from: original,
			policy: .ignoreSigned,
			fetcher: Fetcher<CredentialOfferRequestObject>(),
			metadataResolver: CredentialIssuerMetadataResolver(fetcher: MissingSignedMetadataFetcher())
		)

		#expect(recovered.localizedDescription == original.localizedDescription)
	}
}
