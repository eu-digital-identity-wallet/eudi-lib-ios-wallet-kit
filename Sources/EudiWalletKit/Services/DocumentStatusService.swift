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
import EudiEtsi1196x2
import StatiumSwift
import JSONWebSignature
import SwiftCBOR

public actor DocumentStatusService {
	let statusIdentifier: StatusIdentifier
	/// Trust configuration used to validate the reader/relying-party access certificate chain.
	public let trustConfig: TrustConfiguration
	let date: Date?

	public init(statusIdentifier: StatusIdentifier, date: Date = .now, trustConfig: TrustConfiguration) {
		self.statusIdentifier = statusIdentifier
		self.trustConfig = trustConfig
		self.date = date
	}

	public func getStatus() async throws -> CredentialStatus {
		guard let statusReference: StatusReference = .init(idx: statusIdentifier.idx, uriString: statusIdentifier.uriString) else {
			throw WalletError(description: "Invalid status identifier", code: .invalidStatusToken)
		}
		let getStatus = GetStatus()
		let tokenFetcher = StatusListTokenFetcher(
			verifier: VerifyStatusListTokenSignatureWithTrustManager(trustConfig: trustConfig)
		)
		let result = try await getStatus.getStatus(index: statusReference.idx, url: statusReference.uri, fetchClaims: tokenFetcher.getStatusClaims, clockSkew: trustConfig.clockSkew).get()
		return result
	}
}

struct VerifyStatusListTokenSignatureWithTrustManager: VerifyStatusListTokenSignature {
	public let trustConfig: TrustConfiguration
	func verify(statusListToken: Data, format: StatusListTokenFormat, at: Date) async throws {
		let certsData: [Data]
		switch format {
		case .jwt:
			guard let jwtString = String(data: statusListToken, encoding: .utf8) else { throw JWS.JWSError.invalidString }
			try x5cVerifyJwtSignature.verify(jwt: jwtString)
			let jws = try JWS(jwsString: jwtString)
			guard let b64certs = jws.protectedHeader.x509CertificateChain else { throw JWS.JWSError.somethingWentWrong }
			certsData = b64certs.compactMap { Data(base64Encoded: $0) }
			guard certsData.count == b64certs.count else { throw JWS.JWSError.somethingWentWrong }
		case .cwt:
			let readerAuth = try ReaderAuth(data: [UInt8](statusListToken))
			certsData = readerAuth.x5chain.map { Data($0) }
		}
		guard certsData.count > 0 else { throw JWS.JWSError.somethingWentWrong }
		let (isValid, reason) = await trustConfig.accessTrustManager.validateCertTrustPath(chain: certsData)
		guard isValid else { throw WalletError(description: "\(format) status token trust error: \(reason ?? "")", code: .trustError) }
	}
}


