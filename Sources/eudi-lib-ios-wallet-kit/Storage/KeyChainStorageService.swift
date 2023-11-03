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
/// Implements key-chain storage
public class KeyChainStorageService: DataStorageService {
	public static var defaultId: String = "eudiw"
	var vcService = "eudiw"
	var accessGroup: String?
	
	public init() {}
	
	/// Gets the secret with the id passed in parameter
	/// - Parameters:
	///   - id: The Id of the secret
	///   - itemTypeCode: the item type code for the secret
	///   - accessGroup: the access group for the secret
	/// - Returns: The secret
	public func loadDocument(id: String) throws -> Document {
		var query: [String: Any]
		query = [kSecClass: kSecClassGenericPassword, kSecAttrAccount: id, kSecAttrService: vcService, kSecReturnData: true, kSecReturnAttributes: true] as [String: Any]
		if let accessGroup,	!accessGroup.isEmpty { query[kSecAttrAccessGroup as String] = accessGroup}
		
		var result: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &result)
		let statusMessage = SecCopyErrorMessageString(status, nil) as? String
		guard status == errSecSuccess else {
			throw NSError(domain: "\(KeyChainStorageService.self)", code: Int(status), userInfo: [NSLocalizedDescriptionKey: statusMessage ?? ""])
		}
		let dict = result as! NSDictionary
		var data = dict[kSecValueData] as! Data
		defer { let c = data.count; data.withUnsafeMutableBytes { memset_s($0.baseAddress, c, 0, c); return } }
		return Document(id: dict[kSecAttrAccount] as? String ?? "", label: dict[kSecAttrLabel] as? String ?? "", data: data, createdAt: dict[kSecAttrCreationDate] as! Date, modifiedAt: dict[kSecAttrModificationDate] as? Date)
	}
	
	/// Save the secret to keychain
	/// Note: the value passed in will be zeroed out after the secret is saved
	/// - Parameters:
	///   - id: The Id of the secret
	///   - itemTypeCode: The secret type code (4 chars)
	///   - accessGroup: The access group to use to save secret.
	///   - value: The value of the secret
	public func saveDocument(id: String, label: String, value: inout Data) throws {
		defer { let c = value.count; value.withUnsafeMutableBytes { memset_s($0.baseAddress, c, 0, c); return } }
		// kSecAttrAccount is used to store the secret Id so that we can look it up later
		// kSecAttrService is always set to vcService to enable us to lookup all our secrets later if needed
		// kSecAttrType is used to store the secret type to allow us to cast it to the right Type on search
		var query: [String: Any]
		
		query = [kSecClass: kSecClassGenericPassword, kSecAttrAccount: id, kSecAttrService: vcService, kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecValueData: value, kSecAttrLabel: label] as [String: Any]
		
		if let accessGroup, !accessGroup.isEmpty { query[kSecAttrAccessGroup as String] = accessGroup}
		let status = SecItemAdd(query as CFDictionary, nil)
		let statusMessage = SecCopyErrorMessageString(status, nil) as? String
		guard status == errSecSuccess else {
			throw NSError(domain: "\(KeyChainStorageService.self)", code: Int(status), userInfo: [NSLocalizedDescriptionKey: statusMessage ?? ""])
		}
	}
	
	/// Delete the secret from keychain
	/// Note: the value passed in will be zeroed out after the secret is deleted
	/// - Parameters:
	///   - id: The Id of the secret
	///   - itemTypeCode: The secret type code (4 chars)
	///   - accessGroup: The access group of the secret.
	public func deleteDocument(id: String) throws {
		
		// kSecAttrAccount is used to store the secret Id so that we can look it up later
		// kSecAttrService is always set to vcService to enable us to lookup all our secrets later if needed
		// kSecAttrType is used to store the secret type to allow us to cast it to the right Type on search
		var query = [kSecClass: kSecClassGenericPassword, kSecAttrAccount: id, kSecAttrService: vcService, kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly] as [String: Any]
		
		if let accessGroup,	!accessGroup.isEmpty {
			query[kSecAttrAccessGroup as String] = accessGroup
		}
		
		let status = SecItemDelete(query as CFDictionary)
		let statusMessage = SecCopyErrorMessageString(status, nil) as? String
		guard status == errSecSuccess else {
			throw NSError(domain: "\(KeyChainStorageService.self)", code: Int(status), userInfo: [NSLocalizedDescriptionKey: statusMessage ?? ""])
		}
	}
}
