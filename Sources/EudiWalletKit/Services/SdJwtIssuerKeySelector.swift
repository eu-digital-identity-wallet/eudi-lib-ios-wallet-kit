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
import struct JSONWebKey.JWK

/// Selects the issuer signing key of an SD-JWT VC from the JWT VC Issuer Metadata key set.
enum SdJwtIssuerKeySelector {
	/// With a `kid`, returns the key with that identifier.
	/// Without a `kid`, returns the one key that is not an encryption key.
	/// A `jwk` header narrows the choice to keys with the same key material.
	static func select(from keys: [JWK], keyID: String?, headerKey: JWK?) throws -> JWK {
		if let keyID {
			guard let key = keys.first(where: { $0.keyID == keyID }) else {
				throw WalletError(description: "Unable to resolve issuer signing key for issued SD-JWT", code: .trustError)
			}
			return key
		}
		var candidates = keys.filter { $0.publicKeyUse != .encryption }
		if let headerKey {
			candidates = candidates.filter { sameKeyMaterial($0, headerKey) }
		}
		guard candidates.count == 1, let key = candidates.first else {
			throw WalletError(description: "Issued SD-JWT has no key identifier and the issuer metadata has \(candidates.count) candidate signing keys", code: .trustError)
		}
		return key
	}

	static func sameKeyMaterial(_ a: JWK, _ b: JWK) -> Bool {
		a.keyType == b.keyType && a.curve == b.curve && a.x == b.x && a.y == b.y && a.n == b.n && a.e == b.e
	}
}
