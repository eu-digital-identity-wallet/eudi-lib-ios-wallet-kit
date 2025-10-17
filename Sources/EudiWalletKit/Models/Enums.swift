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
import OpenID4VCI

enum AsWebOutcome: @unchecked Sendable {
	case code(String)
	case presentation_request(URL)
}

enum AuthorizeRequestOutcome: @unchecked Sendable {
	case authorized(AuthorizedRequest)
	case presentation_request(URL)
}

public enum DocTypeIdentifier: Sendable, Hashable, Codable {
	case msoMdoc(docType: String)
	case sdJwt(vct: String)
	case identifier(String)

	/// Extract docType for msoMdoc credentials
	public var docType: String? {
		switch self {
		case .msoMdoc(let docType): return docType
		case .sdJwt, .identifier: return nil
		}
	}

	/// Extract vct for SD-JWT credentials
	public var vct: String? {
		switch self {
		case .sdJwt(let vct): return vct
		case .msoMdoc, .identifier: return nil
		}
	}

	public var docTypeOrVct: String? {
		docType ?? vct
	}
	/// Extract identifier for credential configuration identifiers
	public var configurationIdentifier: String? {
		switch self {
		case .identifier(let id): return id
		case .msoMdoc, .sdJwt: return nil
		}
	}

	/// Get the primary identifier value regardless of type
	public var value: String {
		switch self {
		case .msoMdoc(let docType): return docType
		case .sdJwt(let vct): return vct
		case .identifier(let id): return id
		}
	}
}

