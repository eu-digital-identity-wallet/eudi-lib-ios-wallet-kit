import Foundation
import StatiumSwift
import Testing
@testable import EudiWalletKit

@Suite("Status list token cache")
struct StatusListTokenCacheTests {
	private static let url = URL(string: "https://issuer.example.com/statuslists/1")!
	private static let start = Date(timeIntervalSince1970: 1_800_000_000)

	private final class Clock: @unchecked Sendable {
		private let lock = NSLock()
		private var date = StatusListTokenCacheTests.start
		var now: Date { lock.withLock { date } }
		func advance(_ seconds: TimeInterval) { lock.withLock { date.addTimeInterval(seconds) } }
	}

	private final class Fetcher: @unchecked Sendable {
		private let lock = NSLock()
		private var calls = 0
		let result: Result<StatusListTokenClaims, StatusError>
		init(_ result: Result<StatusListTokenClaims, StatusError>) { self.result = result }
		var count: Int { lock.withLock { calls } }
		var handler: FetchClaimsHandler {
			{ _, _, _ in
				self.lock.withLock { self.calls += 1 }
				return self.result
			}
		}
	}

	private static func claims(ttl: TimeInterval?, exp: TimeInterval?) -> StatusListTokenClaims {
		StatusListTokenClaims(
			subject: url.absoluteString,
			issuedAt: start.timeIntervalSince1970,
			expirationTime: exp.map { start.timeIntervalSince1970 + $0 },
			timeToLive: ttl,
			statusList: StatusList(bytesPerStatus: .one, compressedList: "eNrbuRgAAhcBXQ", aggregationUri: nil)
		)
	}

	/// Fetches twice with `seconds` between the calls and returns the number of network fetches.
	private static func fetchCount(_ result: Result<StatusListTokenClaims, StatusError>, secondsBetween seconds: TimeInterval) async -> Int {
		let clock = Clock()
		let fetcher = Fetcher(result)
		let cache = StatusListTokenCache(now: { clock.now })
		_ = await cache.claims(format: .jwt, url: url, clockSkew: 0, fetch: fetcher.handler)
		clock.advance(seconds)
		_ = await cache.claims(format: .jwt, url: url, clockSkew: 0, fetch: fetcher.handler)
		return fetcher.count
	}

	@Test("a token is reused until its ttl ends")
	func reusesUntilTtl() async {
		#expect(await Self.fetchCount(.success(Self.claims(ttl: 720, exp: nil)), secondsBetween: 719) == 1)
		#expect(await Self.fetchCount(.success(Self.claims(ttl: 720, exp: nil)), secondsBetween: 720) == 2)
	}

	@Test("exp ends the cache before the ttl")
	func expEndsCacheFirst() async {
		#expect(await Self.fetchCount(.success(Self.claims(ttl: 720, exp: 60)), secondsBetween: 61) == 2)
	}

	@Test("a token without ttl and exp is fetched on each check")
	func noLimitNoCache() async {
		#expect(await Self.fetchCount(.success(Self.claims(ttl: nil, exp: nil)), secondsBetween: 0) == 2)
	}

	@Test("a failed fetch is not kept")
	func failureNotCached() async {
		#expect(await Self.fetchCount(.failure(.badServerResponse), secondsBetween: 0) == 2)
	}
}
