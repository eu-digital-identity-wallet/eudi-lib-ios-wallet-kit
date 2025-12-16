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
import Security
import MdocDataModel18013
import JOSESwift

public struct KeyAttestationConfig: Sendable {
	public init(walletAttestationsProvider: any WalletAttestationsProvider, popKeyOptions: KeyOptions? = nil, popKeyDuration: TimeInterval? = nil) {
		self.walletAttestationsProvider = walletAttestationsProvider
		self.popKeyOptions = popKeyOptions
		self.popKeyDuration = popKeyDuration
	}
	public let walletAttestationsProvider: any WalletAttestationsProvider
	public let popKeyOptions: KeyOptions?
	public let popKeyDuration: TimeInterval?
}

public protocol WalletAttestationsProvider: Sendable {
	func getWalletAttestation(key: any JWK) async throws -> String
	func getKeysAttestation(keys: [any JWK], nonce: String?) async throws -> String
}
