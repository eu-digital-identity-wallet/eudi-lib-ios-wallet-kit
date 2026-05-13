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
import MdocSecurity18013
import OpenID4VCI
import X509

public struct TrustedChainValidator: CertificateChainTrust {
    private let iacaRoots: [x5chain]
    public var readerCertificateIssuer: String?
    public var validationMessages: [String] = []

    public init(iacaRoots: [x5chain]) {
        self.iacaRoots = iacaRoots
    }

    public func isValid(chain: [String]) -> Bool {
        var isValid: Bool = false
        let b64certs = chain
        let certsData = b64certs.compactMap { Data(base64Encoded: $0) }
        let certsDer = certsData.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certsDer.count > 0, certsDer.count == b64certs.count else { return false }
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let result = SecTrustCreateWithCertificates(certsDer as CFArray, policy, &trust)
        guard result == errSecSuccess else {
            logger.error("Chain verification error: \(result.message)")
            return false
        }
        (isValid, _, _) = SecurityHelpers.isMdocX5cValid(secCerts: certsDer, usage: .mdocReaderAuth, rootIaca: iacaRoots)
        return isValid
    }
}
