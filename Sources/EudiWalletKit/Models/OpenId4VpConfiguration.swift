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
import struct OpenID4VP.PreregisteredClient
import class OpenID4VP.JWSAlgorithm
import enum OpenID4VP.WebKeySource
import enum OpenID4VP.ResponseEncryptionConfiguration

/// Client identifier scheme for verifier authentication
///
/// Defines different methods for validating and authenticating verifiers
/// during presentation flows.
public enum ClientIdScheme: Sendable {

    /// Client identifier scheme for pre-registered verifiers that are known and trusted by the wallet.
    ///
    /// This scheme allows wallets to maintain a list of trusted verifiers that have been vetted
    /// and approved in advance. It provides the highest level of trust as verifiers are explicitly
    /// whitelisted with their credentials and metadata.
    ///
    /// - Parameter preregisteredClients: List of pre-approved client configurations with their
    ///   client IDs, legal names, API endpoints, and cryptographic parameters
    case preregistered([PreregisteredClient])

    /// Client identifier scheme using X.509 certificate validation with DNS Subject Alternative Names.
    ///
    /// This scheme validates clients using X.509 certificates where the client identifier
    /// matches a DNS name in the certificate's Subject Alternative Name (SAN) extension.
    /// Provides strong cryptographic authentication based on PKI infrastructure.
    case x509SanDns

    /// Client identifier scheme using X.509 certificate hash validation.
    ///
    /// This scheme validates verifiers by comparing the hash of their X.509 certificate
    /// against expected values. Provides certificate-based authentication with additional
    /// integrity verification through hash comparison.
    case x509Hash

    /// Client identifier scheme using redirect URI validation.
    ///
    /// This scheme validates verifiers based on their registered redirect URIs.
    /// The client identifier must match or be associated with a valid redirect URI
    /// that the verifier is authorized to use.
    case redirectUri
}

/// Configuration for OpenID4VP (OpenID for Verifiable Presentations) protocol.
///
/// This structure contains the necessary configuration parameters for implementing
/// the OpenID4VP specification, which enables the presentation of verifiable credentials
/// to relying parties in a standardized way.
public struct OpenId4VpConfiguration: Sendable {
	public let clientIdSchemes: [ClientIdScheme]
	public let responseEncryptionConfiguration: ResponseEncryptionConfiguration?

	public init() {
		self.clientIdSchemes = [.x509SanDns, .x509Hash, .redirectUri]
		self.responseEncryptionConfiguration = nil
	}

	public init(clientIdSchemes: [ClientIdScheme], responseEncryptionConfiguration: ResponseEncryptionConfiguration? = nil) {
		self.clientIdSchemes = clientIdSchemes
		self.responseEncryptionConfiguration = responseEncryptionConfiguration
	}
}

extension PreregisteredClient {
	public init(clientId: String, verifierApiUri: String, verifierLegalName: String) {
		self.init(clientId: clientId, legalName: verifierLegalName, jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUri)/wallet/public-keys.json")!))
	}
}
