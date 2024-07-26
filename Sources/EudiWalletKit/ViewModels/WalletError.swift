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
/// Wallet error
public enum WalletError: LocalizedError {
	case generic(String)

	public init(description: String, userInfo: [String: Any]? = nil) {
		self = .generic(description)
		guard let userInfo else { return }
		var strError: String?
		if let key = userInfo["key"] as? String { strError = NSLocalizedString(key, comment: "") }
		if let s = userInfo["%s"] as? String { strError = strError?.replacingOccurrences(of: "%s", with: NSLocalizedString(s, comment: "")) }
		if let strError { self = .generic(strError) }
	}
	
	public var errorDescription: String? {
		switch self {
		case .generic(let description): description
		}
	}
	
}
