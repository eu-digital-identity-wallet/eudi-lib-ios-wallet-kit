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
	var itemTypeCode: Int?
	
	public init() {}
	
	/// Gets the secret with the id passed in parameter
	/// - Parameters:
	///   - id: The Id of the secret
	///   - itemTypeCode: the item type code for the secret
	///   - accessGroup: the access group for the secret
	/// - Returns: The secret
	public func loadDocument(id: String) throws -> Data {
		var query: [String: Any]
		query = [kSecClass: kSecClassGenericPassword, kSecAttrAccount: id, kSecAttrService: vcService, kSecReturnData: true] as [String: Any]
		if let accessGroup,	!accessGroup.isEmpty { query[kSecAttrAccessGroup as String] = accessGroup}
		if let itemTypeCode { query[kSecAttrType as String] = itemTypeCode}
		
		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		let statusMessage = SecCopyErrorMessageString(status, nil) as? String
		guard status == errSecSuccess else {
			throw NSError(domain: "\(KeyChainStorageService.self)", code: Int(status), userInfo: [NSLocalizedDescriptionKey: statusMessage ?? ""])
		}
		guard var value = item as? Data else { throw NSError(domain: "\(KeyChainStorageService.self)", code: Int(0), userInfo: [NSLocalizedDescriptionKey: "Invalid item \(id)"]) }
		defer { let c = value.count; value.withUnsafeMutableBytes { memset_s($0.baseAddress, c, 0, c); return } }
		return value
	}
	
	/// Save the secret to keychain
	/// Note: the value passed in will be zeroed out after the secret is saved
	/// - Parameters:
	///   - id: The Id of the secret
	///   - itemTypeCode: The secret type code (4 chars)
	///   - accessGroup: The access group to use to save secret.
	///   - value: The value of the secret
	public func saveDocument(id: String, value: inout Data) throws {
		defer { let c = value.count; value.withUnsafeMutableBytes { memset_s($0.baseAddress, c, 0, c); return } }
		// kSecAttrAccount is used to store the secret Id so that we can look it up later
		// kSecAttrService is always set to vcService to enable us to lookup all our secrets later if needed
		// kSecAttrType is used to store the secret type to allow us to cast it to the right Type on search
		var query: [String: Any]
		
		query = [kSecClass: kSecClassGenericPassword, kSecAttrAccount: id, kSecAttrService: vcService, kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecValueData: value] as [String: Any]
		
		if let accessGroup,	!accessGroup.isEmpty { query[kSecAttrAccessGroup as String] = accessGroup}
		if let itemTypeCode { query[kSecAttrType as String] = itemTypeCode}
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
		if let itemTypeCode { query[kSecAttrType as String] = itemTypeCode}
		
		let status = SecItemDelete(query as CFDictionary)
		let statusMessage = SecCopyErrorMessageString(status, nil) as? String
		guard status == errSecSuccess else {
			throw NSError(domain: "\(KeyChainStorageService.self)", code: Int(status), userInfo: [NSLocalizedDescriptionKey: statusMessage ?? ""])
		}
	}
}
