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

/// Configuration that describes where trust anchors come from and how trust failures are handled.
public struct TrustConfiguration: Sendable {
    /// The policy applied to doc types without a specific entry in `docTypePolicies`.
    public let defaultPolicy: TrustPolicy
    /// Per doc-type overrides of `defaultPolicy`, keyed by doc type.
    public let docTypePolicies: [String: TrustPolicy]
	/// Require signed metadata
	public let requireSignedMetadata: Bool
	/// Clock skew for the status token verifier
	public let clockSkew: TimeInterval
	
    /// Trust manager for issuer (document-signer) certificates. Falls back to the `default`
    /// doc-type mappings only when the trust source does not already define its own.
    /// When a `fallbackTrustSource` is supplied it is consulted for doc types this manager
    /// has no validation context for.
    public var issuerTrustManager: EtsiTrustManager

    /// Trust manager for reader/relying-party access certificates. Uses the WRPAC verification context.
    public let accessTrustManager: EtsiTrustManager

    public init(
        trustSource: TrustSource,
		fallbackTrustSource: TrustSource?,
        defaultPolicy: TrustPolicy = .enforce,
        docTypePolicies: [String: TrustPolicy] = [:],
		requireSignedMetadata: Bool = true,
		clockSkew: TimeInterval = 60
    ) {
        self.defaultPolicy = defaultPolicy
        self.docTypePolicies = docTypePolicies
		self.requireSignedMetadata = requireSignedMetadata
		self.clockSkew = clockSkew
        let issuerSource = trustSource.contextTypeMappings == nil ? trustSource.withContextTypeMappings(.default) : trustSource
        let fallbackTrustManager: EtsiTrustManager?
		if let fallbackTrustSource {
			let fallbackTrustSource1 = fallbackTrustSource.contextTypeMappings == nil ? fallbackTrustSource.withContextTypeMappings(.default) : fallbackTrustSource
			fallbackTrustManager = EtsiTrustManager(source: fallbackTrustSource1)
		} else {
			fallbackTrustManager = nil
		}
        issuerTrustManager = EtsiTrustManager(source: issuerSource, fallback: fallbackTrustManager)
        accessTrustManager = EtsiTrustManager(source: trustSource.withContextTypeMappings(nil))
    }

    /// The trust policy effective for the given doc type, falling back to `defaultPolicy`.
    public func policy(for docType: String) -> TrustPolicy {
        docTypePolicies[docType] ?? defaultPolicy
    }

    /// The OpenID4VCI issuer-metadata signature policy derived from this configuration.
    ///
    /// When `requireSignedMetadata` is set the issuer metadata must be signed and its signing
    /// certificate chain is validated against the issuer trust anchors; otherwise signing is ignored.
    public var issuerMetadataPolicy: IssuerMetadataPolicy {
        guard requireSignedMetadata else { return .ignoreSigned }
        let chainTrust = IssuerMetadataChainTrust(trustManager: accessTrustManager)
        return .requireSigned(issuerTrust: .byCertificateChain(certificateChainTrust: chainTrust))
    }
}

