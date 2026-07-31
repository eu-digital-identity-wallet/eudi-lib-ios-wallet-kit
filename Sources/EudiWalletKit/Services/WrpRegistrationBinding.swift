// Copyright (c) 2026 European Commission
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import X509
import SwiftASN1

extension WrpRegistrationPolicy {
    /// Whether this registration certificate is bound to the relying party that presents it.
    ///
    /// - Parameter accessCertificate: The leaf access certificate that signed the request; when nil the
    ///   registration is treated as unbound.
    func isBound(to accessCertificate: Certificate?) -> Bool {
        guard let accessCertificate, let presenterId = accessCertificate.subjectIdentifier() else {
            return false
        }
        if let intermediary {
            return intermediary.identifier == presenterId
        }
        return identifiers.contains { $0.value == presenterId }
    }
}

// OID 2.5.4.97 — organizationIdentifier
private let oidOrganizationIdentifier: ASN1ObjectIdentifier = [2, 5, 4, 97]
// OID 2.5.4.5 — serialNumber
private let oidSerialNumber = ASN1ObjectIdentifier.NameAttributes.serialNumber

private extension Certificate {
    func subjectIdentifier() -> String? {
        firstRdnValue(oid: oidOrganizationIdentifier)
            ?? firstRdnValue(oid: oidSerialNumber)
    }

    func firstRdnValue(oid: ASN1ObjectIdentifier) -> String? {
        for relativeDistinguishedName in subject {
            for attribute in relativeDistinguishedName where attribute.type == oid {
                if let value = String(attribute.value) {
                    return value
                }
            }
        }
        return nil
    }
}
