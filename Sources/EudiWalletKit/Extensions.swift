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

extension FileManager {
	public static func getCachesDirectory() throws -> URL {
			let paths = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)
			guard paths.count > 0 else {
				throw WalletError(description: "No downloads directory found")
			}
			return paths[0]
	}
}


