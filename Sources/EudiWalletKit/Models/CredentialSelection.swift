/*
 *  Copyright (c) 2023-2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import Foundation
import MdocDataModel18013
import OpenID4VP
import OrderedCollections
import struct WalletStorage.Document

public typealias CredentialSelectionSet = OrderedSet<CredentialSelection>
public typealias CredentialSelectionSetOptions = OrderedDictionary<String, CredentialSelectionSet>


public struct CredentialSelection: Sendable, Hashable {
	public let credentialId: Document.ID
	public let docType: DocType
	public let queryId: QueryId
	public let optionId: String
	public let claimQueries: [ClaimsQuery]

	public init(credentialId: Document.ID, docType: DocType, queryId: QueryId, optionId: String, claimQueries: [ClaimsQuery]) {
		self.credentialId = credentialId
		self.docType = docType
		self.queryId = queryId
		self.optionId = optionId
		self.claimQueries = claimQueries
	}

	public static func == (lhs: CredentialSelection, rhs: CredentialSelection) -> Bool {
		lhs.credentialId == rhs.credentialId
	}

	public func hash(into hasher: inout Hasher) {
		hasher.combine(credentialId)
	}
}