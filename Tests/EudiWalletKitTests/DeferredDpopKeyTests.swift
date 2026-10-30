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
import Testing

@testable import EudiWalletKit

@Suite("DPoP key of a deferred issuance")
struct DeferredDpopKeyTests {
	let issuerId = "https://issuer.example.com"

	func makeConfig(dpopUsesClientAttestationKey: Bool) -> OpenId4VciConfiguration {
		OpenId4VciConfiguration(
			credentialIssuerURL: issuerId,
			keyAttestationsConfig: KeyAttestationConfiguration(walletAttestationsProvider: RecordingWalletAttestationsProvider()),
			dpopUsesClientAttestationKey: dpopUsesClientAttestationKey)
	}

	@Test("The stored client attestation key signs the deferred request")
	func storedAttestationKey() {
		let attestationKeyId = OpenId4VciConfiguration.generatePopKeyId(popUsage: .clientAttestation, credentialIssuerId: issuerId)
		let key = makeConfig(dpopUsesClientAttestationKey: false).deferredDpopKey(storedKeyId: attestationKeyId, credentialIssuerId: issuerId)
		#expect(key.id == attestationKeyId)
	}

	@Test("A record without a key id keeps the per-issuer DPoP key when the option is on")
	func recordWithoutKeyId() {
		let key = makeConfig(dpopUsesClientAttestationKey: true).deferredDpopKey(storedKeyId: nil, credentialIssuerId: issuerId)
		#expect(key.id == OpenId4VciConfiguration.generatePopKeyId(popUsage: .dpop, credentialIssuerId: issuerId))
	}

	@Test("A record from before the key id decodes with a nil key id")
	func decodeOldRecord() throws {
		let json = #"{"deferredCredentialEndpoint":"https://issuer.example.com/deferred","transactionId":{"value":"tx-1"},"publicKeys":[],"timeStamp":0}"#
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: Data(json.utf8))
		#expect(model.dpopKeyId == nil)
	}

	@Test("The key id survives storage")
	func roundTrip() throws {
		let json = #"{"deferredCredentialEndpoint":"https://issuer.example.com/deferred","transactionId":{"value":"tx-1"},"publicKeys":[],"timeStamp":0,"dpopKeyId":"client-attestation-1"}"#
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: Data(json.utf8))
		let decoded = try JSONDecoder().decode(DeferredIssuanceModel.self, from: JSONEncoder().encode(model))
		#expect(decoded.dpopKeyId == "client-attestation-1")
	}
}
