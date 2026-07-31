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
import MdocSecurity18013
import Security
import StatiumSwift
import SwiftCBOR
import JSONWebSignature
import Logging
import struct MdocDataModel18013.StatusList

public actor DocumentStatusService {
	let statusList: StatusList
	/// Trust configuration used to validate the reader/relying-party access certificate chain.
	public let trustConfig: TrustConfiguration
	let date: Date?
	private static let logger = Logger(label: "DocumentStatusService")

	public init(statusList: StatusList, date: Date = .now, trustConfig: TrustConfiguration) {
		self.statusList = statusList
		self.trustConfig = trustConfig
		self.date = date
	}

	public func getStatus() async throws -> CredentialStatus {
		guard let statusReference: StatusReference = .init(idx: statusList.idx, uriString: statusList.uri) else {
			throw WalletError(description: "Invalid status identifier", code: .invalidStatusToken)
		}
		let getStatus = GetStatus()
		let tokenFetcher = StatusListTokenFetcher(
			verifier: StatusListTokenSignatureVerifier(trustConfig: trustConfig)
		)
		let result = await getStatus.getStatus(index: statusReference.idx, url: statusReference.uri, fetchClaims: tokenFetcher.getStatusClaims, clockSkew: trustConfig.clockSkew)
		switch result {
			case .success(let status): return status
			case .failure(let error): throw WalletError(description: "Status check failed", code: .statusCheckFailed, innerError: error)
		}
	}
}

struct StatusListTokenSignatureVerifier: VerifyStatusListTokenSignature {
	let trustConfig: TrustConfiguration
	private static let logger = Logger(label: "StatusListTokenSignatureVerifier")

	func verify(statusListToken: Data, format: StatusListTokenFormat, at: Date) async throws {
		let attTF: AttestToken.Format = switch format { case .jwt: .jwt; case .cwt: .cwt }
		let att = try x5cVerifyJwtOrCwt.parse(attestData: statusListToken, format: attTF)
		let (isValid, reason) = try await x5cVerifyJwtOrCwt.validateTrust(att, trustValidator: trustConfig.accessTrustManager)
		guard isValid else {
			let message = "\(format) status token trust error: \(reason ?? "")"
			switch trustConfig.statusTrustPolicy {
			case .warning: Self.logger.warning("\(message)"); return
			case .enforce: throw WalletError(description: message, code: .trustError)
			}
		}
	}
}



