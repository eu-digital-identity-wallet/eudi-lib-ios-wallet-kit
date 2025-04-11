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
import MdocDataModel18013
import eudi_lib_ios_statium_swift

public actor DocumentStatusService {
	let statusIdentifier: StatusIdentifier
	let verifier: VerifyStatusListTokenSignature?
	let date: Date?
	
	public init(statusIdentifier: StatusIdentifier, date: Date = .now, verifier: VerifyStatusListTokenSignature? = nil) {
		self.statusIdentifier = statusIdentifier
		self.verifier = verifier
		self.date = date
	}
	
	public func getStatus() async throws -> CredentialStatus {
		guard let statusReference: StatusReference = .init(idx: statusIdentifier.idx, uriString: statusIdentifier.uriString) else {
			throw WalletError(description: "Invalid status identifier")
		}
		let getStatus = GetStatus()
		let tokenFetcher = StatusListTokenFetcher(verifier: verifier ?? VerifyStatusListTokenSignatureIgnore())
		let result = try await getStatus.getStatus(index: statusReference.idx, url: statusReference.uri, fetchClaims: tokenFetcher.getStatusClaims).get()
		return result
	}
}

struct VerifyStatusListTokenSignatureIgnore: VerifyStatusListTokenSignature {
	func verify(statusListToken: String, format: StatusListTokenFormat,at: Date) throws {
		// No verification logic, ignore the signature
	}
}
