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
import OpenID4VCI
import JOSESwift

public protocol WalletAttestationsProvider: Sendable {
	func getWalletAttestation(signingKey: SigningKeyProxy) async throws -> String
	func getKeysAttestation(keys: [any JWK], nonce: String?) async throws -> String
	/// Whether credential-key attestation needs private-key proofs.
	var requiresKeyProofs: Bool { get }
	/// Signing handles follow the public-key order and keep private material in the secure area.
	func getKeysAttestation(keys: [any JWK], signingKeys: [SigningKeyProxy], nonce: String?) async throws -> String
}

public extension WalletAttestationsProvider {
	var requiresKeyProofs: Bool { false }

	/// Existing providers can continue to attest public keys without signing proofs.
	func getKeysAttestation(keys: [any JWK], signingKeys: [SigningKeyProxy], nonce: String?) async throws -> String {
		try await getKeysAttestation(keys: keys, nonce: nonce)
	}
}
