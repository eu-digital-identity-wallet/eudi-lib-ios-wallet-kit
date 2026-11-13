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
import WalletStorage
@testable import EudiWalletKit

struct PartialIssuanceTests {
	private enum Failure: Error { case rejected }

	private static func document(_ id: String) -> WalletStorage.Document {
		WalletStorage.Document(id: id, docType: "pid", docDataFormat: .cbor, data: Data(), docKeyInfo: nil, createdAt: nil, metadata: nil, displayName: nil, status: .issued)
	}

	@Test func failureDoesNotCancelLaterSuccessAndRetainsConfiguration() async throws {
		let operations: [@Sendable () async throws -> WalletStorage.Document] = [
			{ Self.document("first") },
			{ throw Failure.rejected },
			{
				try await Task.sleep(for: .milliseconds(20))
				try Task.checkCancellation()
				return Self.document("last")
			}
		]
		let outcomes = await OpenId4VciService.collectIssuanceOutcomes(operations)
		let result = try DocumentIssuanceResult(outcomes: outcomes, configurations: ["mdoc", "sdjwt", "other"], docTypes: ["pid", "pid", "other"])
		#expect(result.documents.map(\.id) == ["first", "last"])
		#expect(result.failures.map(\.configurationIdentifier) == ["sdjwt"])
		#expect(result.failures.first?.error is Failure)
		let response = IssuerResponse(documents: result.documents, failures: result.failures, wrpIssuerWarnings: nil)
		#expect(response.failures.count == 1)
	}

	@Test func allFailuresThrowOriginalError() async {
		let outcomes: [Result<WalletStorage.Document, Error>] = [.failure(Failure.rejected)]
		#expect(throws: Failure.self) {
			try DocumentIssuanceResult(outcomes: outcomes, configurations: ["pid"], docTypes: ["pid"])
		}
	}

	@Test func allSuccessesRemainSuccessful() throws {
		let result = try DocumentIssuanceResult(outcomes: [.success(Self.document("pid"))], configurations: ["mdoc"], docTypes: ["pid"])
		#expect(result.documents.map(\.id) == ["pid"])
		#expect(result.failures.isEmpty)
	}
}
