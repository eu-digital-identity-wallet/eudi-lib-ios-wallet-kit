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
import OpenID4VP
import struct WalletStorage.Document

public protocol DcqlQueryable {
	/// retrieve credential identifiers matching docType and dataFormat
	func getCredentials(docOrVctType: DocType, docDataFormat: DocDataFormat) -> [Document.ID]
	/// retrieve all claim paths for a given credential identifier
	func getAllClaimPaths(id: Document.ID) -> [ClaimPath]
	/// check if a claim exists for a given credential identifier and claim path
	func hasClaim(id: Document.ID, claimPath: ClaimPath) -> Bool
	/// check if a claim exists for a given credential identifier and claim path and value
	func hasClaimWithValue(id: Document.ID, claimPath: ClaimPath, values: [String]) -> Bool
}

public class DefaultDcqlQueryable: DcqlQueryable {
	private let credentials: [Document.ID: (docType: DocType, format: DocDataFormat)]
	private let claimPaths: [Document.ID: [ClaimPath]]
	private let claimValues: [Document.ID: [ClaimPath: [String]]]

	public init(credentials: [Document.ID: (DocType, DocDataFormat)], claimPaths: [Document.ID: [ClaimPath]], claimValues: [Document.ID: [ClaimPath: [String]]] = [:]) {
		self.credentials = credentials
		self.claimPaths = claimPaths
		self.claimValues = claimValues
	}

	public func getCredentials(docOrVctType: DocType, docDataFormat: DocDataFormat) -> [Document.ID] {
		credentials.filter { _, value in
			value.docType == docOrVctType && value.format == docDataFormat
		}.map { $0.key }
	}

	public func getAllClaimPaths(id: Document.ID) -> [ClaimPath] {
		claimPaths[id] ?? []
	}

	public func hasClaim(id: Document.ID, claimPath: ClaimPath) -> Bool {
		guard let paths = claimPaths[id] else { return false }
		return paths.contains { $0.value == claimPath.value || claimPath.contains2($0) }
	}

	public func hasClaimWithValue(id: Document.ID, claimPath: ClaimPath, values: [String]) -> Bool {
		guard let claimValueMap = claimValues[id],
		      let availableValues = claimValueMap[claimPath] else {
			return false
		}
		return values.contains { availableValues.contains($0) }
	}
}
