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
import struct WalletStorage.Document

public typealias CredentialSelections = [Document.ID: CredentialSelection]
public typealias CredentialSelectionSet = Set<CredentialSelection>
public typealias CredentialSelectionSetOptions = [String: CredentialSelectionSet]

extension CredentialSelectionSet {
	public subscript(credentialId: Document.ID) -> CredentialSelection? {
		first { $0.credentialId == credentialId }
	}
}

extension CredentialSelectionSetOptions {
	/// Finds a CredentialSelection by credential ID across all sets.
	public subscript(credentialId: Document.ID) -> CredentialSelection? {
		values.lazy.compactMap { $0[credentialId] }.first
	}

	/// Total number of unique credentials across all sets.
	public var count: Int {
		Set(values.flatMap { $0.map(\.credentialId) }).count
	}
}

public struct CredentialSelection: Sendable, Hashable, RandomAccessCollection {
	public typealias Element = ClaimsQuery
	public typealias Index = Array<ClaimsQuery>.Index

	public let credentialId: Document.ID
	public let docType: DocType
	public let queryId: QueryId
	public let claimQueries: [ClaimsQuery]

	public init(credentialId: Document.ID, docType: DocType, queryId: QueryId, claimQueries: [ClaimsQuery]) {
		self.credentialId = credentialId
		self.docType = docType
		self.queryId = queryId
		self.claimQueries = claimQueries
	}

	public var startIndex: Index { claimQueries.startIndex }
	public var endIndex: Index { claimQueries.endIndex }
	public func index(after i: Index) -> Index { claimQueries.index(after: i) }
	public subscript(position: Index) -> ClaimsQuery { claimQueries[position] }

	public static func == (lhs: CredentialSelection, rhs: CredentialSelection) -> Bool {
		lhs.credentialId == rhs.credentialId
	}

	public func hash(into hasher: inout Hasher) {
		hasher.combine(credentialId)
	}
}