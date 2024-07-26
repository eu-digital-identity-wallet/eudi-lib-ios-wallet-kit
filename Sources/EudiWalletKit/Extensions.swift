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
import OpenID4VCI
import WalletStorage

extension String {
	public func translated() -> String {
		NSLocalizedString(self, comment: "")
	}
}

extension Array where Element == Display {
	func getName() -> String? {
		(first(where: { $0.locale == Locale.current }) ?? first)?.name
	}
}

extension Bundle {
	func getURLSchemas() -> [String]? {
		guard let urlTypes = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String:Any]], let schema = urlTypes.first, let urlSchemas = schema["CFBundleURLSchemes"] as? [String] else {return nil}
		return urlSchemas
	}
}

extension WalletStorage.Document {
	public var authorizePresentationUrl: String? {
		guard status == .pending, let model = try? JSONDecoder().decode(PendingIssuanceModel.self, from: data), case .presentation_request_url(let urlString) = model.pendingReason else { return nil	}
		return urlString
	}
}
