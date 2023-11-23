 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */
 

//  TransferStatus.swift

import Foundation

/// Data exchange flow type
public enum FlowType: Codable, Hashable {
	
	case ble
	case openid4vp(qrCode: Data)
	/// True if proximity flow type (currently ``ble``)
	public var isProximity: Bool { switch self { case .ble: true; default: false } }
	public var qrCode: Data? { if case let .openid4vp(qrCode) = self { qrCode} else { nil} }
}

/// Data format of the exchanged data
public enum DataFormat: String {
	case cbor = "cbor"
	case sjwt = "sjwt"
}

public enum StorageType {
	case keyChain
}


