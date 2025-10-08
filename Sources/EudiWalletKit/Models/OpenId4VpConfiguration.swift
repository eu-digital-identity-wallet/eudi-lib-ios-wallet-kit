import Foundation
import struct SiopOpenID4VP.PreregisteredClient
import class SiopOpenID4VP.JWSAlgorithm
import enum SiopOpenID4VP.WebKeySource

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

public struct OpenId4VpConfiguration: Sendable {
	let clientIdSchemes: [ClientIdScheme]
	public init() {
		self.clientIdSchemes = [.x509SanDns, .x509Hash]
	}
	public init(clientIdSchemes: [ClientIdScheme]) {
		self.clientIdSchemes = clientIdSchemes
	}
}

extension PreregisteredClient {
	public init(clientId: String, verifierApiUri: String, verifierLegalName: String) {
		self.init(clientId: clientId, legalName: verifierLegalName, jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUri)/wallet/public-keys.json")!))
	}
}
