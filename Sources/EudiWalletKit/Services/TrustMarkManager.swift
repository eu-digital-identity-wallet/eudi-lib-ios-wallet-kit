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
import MdocDataModel18013

/// Resolves Trust Mark information and downloads its graphics and localized text metadata.
/// This retrieves display information; it does not independently verify wallet certification.
public final class TrustMarkManager: Sendable {
	private let source: TrustMarkSource
	private let networking: any NetworkingProtocol

	public init(source: TrustMarkSource, networking: any NetworkingProtocol = URLSession.shared) {
		self.source = source
		self.networking = networking
	}

	/// Resolves the source and fetches the resource on each call, using the networking client's cache policy.
	/// Provider, transport, cancellation, and decoding errors propagate to the caller.
	/// Throws `URLError.badURL` for invalid resource URLs and `URLError.badServerResponse`
	/// for non-HTTP or unsuccessful HTTP responses.
	public func getTrustMark() async throws -> TrustMark {
		try Task.checkCancellation()
		let information: TrustMarkInformation
		switch source {
		case .static(let value):
			information = value
		case .dynamic(let provider):
			information = try await provider.getTrustMarkInformation()
		}
		try Task.checkCancellation()
		guard let url = URL(string: information.trustMarkResourceURL),
			["https", "http"].contains(url.scheme?.lowercased() ?? ""),
			let host = url.host, !host.isEmpty else {
			throw URLError(.badURL)
		}
		let (data, response) = try await networking.data(from: url)
		try Task.checkCancellation()
		guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode) else {
			throw URLError(.badServerResponse)
		}
		let resource = try JSONDecoder().decode(TrustMarkResource.self, from: data)
		return TrustMark(information: information, resource: resource)
	}
}
