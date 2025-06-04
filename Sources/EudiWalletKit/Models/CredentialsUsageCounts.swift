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

public struct CredentialsUsageCounts: Codable, Sendable {
    public let total: Int
    public let remaining: Int
    public var used: Int  { total - remaining }

    public init(total: Int, remaining: Int) throws {
        self.total = total
        self.remaining = remaining
		if total < remaining {
			throw WalletError(description: "Total count cannot be less than remaining count")
		}
    }
}