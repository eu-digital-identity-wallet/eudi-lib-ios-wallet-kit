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

Created on 09/11/2023
*/
import Foundation

extension String {
	public func translated() -> String {
		NSLocalizedString(self, comment: "")
	}
}

/// Calls a Security framework function that returns `nil` on error along with a `CFError` indirectly.
///
/// For example, the `SecKeyCreateDecryptedData` function has a signature like this:
///
/// ```
/// func SecKeyCreateDecryptedData(…, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?
/// ```
///
/// and so you call it like this:
///
/// ```
/// let plainText = try secCall { SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, cypherText, $0) }
/// ```
///
/// - Parameter body: A function that returns a value, which returns `nil` if
/// there’s an error and, in that case, places a `CFError` value in the ‘out’ parameter.
/// - Throws: If `body` returns `nil`.
/// - Returns: On success, the non-`nil` value returned by `body`.

func secCall<Result>(_ body: (_ resultPtr: UnsafeMutablePointer<Unmanaged<CFError>?>) -> Result?) throws -> Result {
		var errorQ: Unmanaged<CFError>? = nil
		guard let result = body(&errorQ) else {
				throw errorQ!.takeRetainedValue() as Error
		}
		return result
}



