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
import WalletStorage

/// A failed credential configuration from a multi-document issuance attempt.
public struct DocumentIssuanceFailure: Sendable {
	public let configurationIdentifier: String
	public let docType: String?
	public let error: any Error
}

/// Stored documents and individual failures, in the order requested.
public struct DocumentIssuanceResult: Sendable {
	public let documents: [WalletStorage.Document]
	public let failures: [DocumentIssuanceFailure]

	init(documents: [WalletStorage.Document], failures: [DocumentIssuanceFailure]) {
		self.documents = documents
		self.failures = failures
	}

	init(outcomes: [Result<WalletStorage.Document, Error>], configurations: [String], docTypes: [String?]) throws {
		var documents = [WalletStorage.Document]()
		var failures = [DocumentIssuanceFailure]()
		for (index, outcome) in outcomes.enumerated() {
			switch outcome {
			case .success(let document): documents.append(document)
			case .failure(let error):
				failures.append(DocumentIssuanceFailure(configurationIdentifier: configurations[index], docType: docTypes[index], error: error))
			}
		}
		// Preserve original error types, including authentication errors used by reissuance retries.
		if documents.isEmpty, let failure = failures.first { throw failure.error }
		self.init(documents: documents, failures: failures)
	}
}
