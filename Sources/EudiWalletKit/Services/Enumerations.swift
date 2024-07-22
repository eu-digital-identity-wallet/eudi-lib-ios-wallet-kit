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

//  TransferStatus.swift

import Foundation
import WalletStorage

/// Data exchange flow type
public enum FlowType: Codable, Hashable {
	
	case ble
	case openid4vp(qrCode: Data)
	case other
	/// True if proximity flow type (currently ``ble``)
	public var isProximity: Bool { switch self { case .ble: true; default: false } }
	public var qrCode: Data? { if case let .openid4vp(qrCode) = self { qrCode} else { nil} }
}

/// Data format of the exchanged data
public enum DataFormat: String {
	case cbor = "cbor"
	case sdjwt = "sdjwt"
}

public extension DataFormat {
	init?(_ docDataType: DocDataType) {
		switch docDataType {
		case .cbor:	self = .cbor
		case .sjwt:	self = .sdjwt
		default: return nil
		}
	}
}

public enum StorageType {
	case keyChain
}


