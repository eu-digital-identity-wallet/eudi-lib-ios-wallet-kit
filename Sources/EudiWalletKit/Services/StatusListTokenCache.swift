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
import StatiumSwift

/// Keeps verified status list token claims per URL, format, owner and trust configuration until the token `ttl` or `exp` ends.
public actor StatusListTokenCache {
	private struct Key: Hashable {
		let url: URL
		let isJWT: Bool
		let owner: StatusListOwner?
		let trustScope: UUID?
	}
	private var entries: [Key: (claims: StatusListTokenClaims, until: Date)] = [:]
	private let now: @Sendable () -> Date

	public init(now: @escaping @Sendable () -> Date = { Date() }) {
		self.now = now
	}

	/// Returns the cached claims for `url`, or fetches them. The cache does not keep failures.
	func claims(format: StatusListTokenFormat, url: URL, clockSkew: TimeInterval, owner: StatusListOwner? = nil, trustScope: UUID? = nil, fetch: FetchClaimsHandler) async -> Result<StatusListTokenClaims, StatusError> {
		let isJWT: Bool = switch format { case .jwt: true; case .cwt: false }
		let key = Key(url: url, isJWT: isJWT, owner: owner, trustScope: trustScope)
		if let entry = entries[key], entry.until > now() {
			return .success(entry.claims)
		}
		let result = await fetch(format, url, clockSkew)
		if case .success(let claims) = result, let until = Self.cacheLimit(of: claims, fetchedAt: now()) {
			entries[key] = (claims, until)
		} else {
			entries[key] = nil
		}
		return result
	}

	/// The earlier of `ttl` after the fetch and `exp`. Nil when the token has neither.
	static func cacheLimit(of claims: StatusListTokenClaims, fetchedAt date: Date) -> Date? {
		let ttlLimit = claims.timeToLive.map { date.addingTimeInterval($0) }
		let expLimit = claims.expirationTime.map { Date(timeIntervalSince1970: $0) }
		return [ttlLimit, expLimit].compactMap(\.self).min()
	}
}
