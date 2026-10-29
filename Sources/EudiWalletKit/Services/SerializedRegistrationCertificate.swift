/*
 Copyright (c) 2026 European Commission

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
import MdocDataModel18013
import MdocSecurity18013

enum SerializedRegistrationCertificate {
    /// OpenID4VP/VCI carry serialized JWT or CWT certificates as base64url.
    static func decode(_ value: String) -> Data? {
        guard !value.isEmpty else { return nil }
        if value.wholeMatch(of: x5cVerifyJwtOrCwt.compactJWSRegex) != nil {
            return value.data(using: .ascii)
        }
        return Data(base64URLEncoded: value)
    }
}
