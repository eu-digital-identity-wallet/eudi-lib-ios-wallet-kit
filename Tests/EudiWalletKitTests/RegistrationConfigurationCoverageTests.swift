import Foundation
import MdocDataModel18013
import MdocSecurity18013
import JOSESwift
import OpenID4VCI
import struct OpenID4VP.DCQL
import Testing
import X509
@testable import EudiWalletKit

@Suite("Registration and trust configuration coverage")
struct RegistrationConfigurationCoverageTests {
    private func trustConfig(vp: TrustPolicy = .enforce, vci: TrustPolicy = .enforce, signedMetadata: Bool = true) -> TrustConfiguration {
        #if canImport(EudiEtsi1196x2)
        TrustConfiguration(
            trustSource: .etsi(.eudiRef), defaultPolicy: .warning,
            docTypePolicies: ["pid": .enforce], requireSignedMetadata: signedMetadata,
            statusTrustPolicy: .warning, wrprcVpTrustPolicy: vp,
            wrprcVciTrustPolicy: vci, clockSkew: 17
        )
        #else
        TrustConfiguration(
            rootIaca: [], defaultPolicy: .warning,
            docTypePolicies: ["pid": .enforce], requireSignedMetadata: signedMetadata,
            statusTrustPolicy: .warning, wrprcVpTrustPolicy: vp,
            wrprcVciTrustPolicy: vci, clockSkew: 17
        )
        #endif
    }

    private func isEnforce(_ policy: TrustPolicy) -> Bool {
        if case .enforce = policy { return true }
        return false
    }

    @Test("Trust policies apply doc-type overrides and signed metadata preference")
    func trustPolicyDefaultsAndOverrides() {
        let required = trustConfig()
        #expect(isEnforce(required.policy(for: "pid")))
        #expect(!isEnforce(required.policy(for: "mdl")))
        #expect(required.requireSignedMetadata)
        #expect(required.clockSkew == 17)
        #expect(!isEnforce(required.statusTrustPolicy))
        #expect(isEnforce(required.wrprcVpTrustPolicy))
        #expect(isEnforce(required.wrprcVciTrustPolicy))

        let ignored = trustConfig(signedMetadata: false)
        if case .ignoreSigned = ignored.issuerMetadataPolicy {} else {
            Issue.record("Expected unsigned metadata to be accepted when signature verification is disabled")
        }
    }

    @Test("WRPRC VCI failures grant warnings or deny issuance according to policy")
    func vciValidationFailurePolicy() async throws {
        let warningValidator = WrpVciRegistrationValidator(trustConfig: trustConfig(vci: .warning))
        let warning = await warningValidator.validateCertificate(wrpac: "invalid-base64", wrprc: "not-a-token", offeredConfigurations: [:])
        guard case .granted(let warnings) = warning else {
            Issue.record("Warning mode should allow issuance while returning validation warnings")
            return
        }
        #expect(warnings[""]?.isEmpty == false)
        let warningViolations = await warningValidator.wrpVciWarnings[""] ?? []
        #expect(warningViolations.contains { $0.reason == .wrpacDecodingFailed })

        let enforcingValidator = WrpVciRegistrationValidator(trustConfig: trustConfig(vci: .enforce))
        let denied = await enforcingValidator.validateCertificate(wrpac: "invalid-base64", wrprc: "not-a-token", offeredConfigurations: [:])
        guard case .notGranted = denied else {
            Issue.record("Enforce mode should deny malformed registration certificates")
            return
        }
        let enforcingViolations = await enforcingValidator.wrpVciWarnings[""] ?? []
        #expect(enforcingViolations.contains { $0.reason == .wrpacDecodingFailed })
    }

    @Test("VP validation resets state and applies warning and enforce policy to malformed certificates")
    func vpValidationFailurePolicy() async throws {
        let certificateData = try #require(Data(name: "pidissuerca02_ut", ext: "der", from: Bundle.module))
        let certificate = try Certificate(derEncoded: Array(certificateData))
        let dcqlData = try #require(Data(name: "dcql-vehicle", ext: "json", from: Bundle.module))
        let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)

        let warningValidator = WrpVpRegistrationValidator(trustConfig: trustConfig(vp: .warning))
        let allowed = await warningValidator.validateCertificate(wrpac: certificate, wrprc: "not-a-token", dcql: dcql)
        guard case .granted(let warnings) = allowed else {
            Issue.record("Warning mode should allow malformed WRPRCs with warnings")
            return
        }
        #expect(warnings["stale"] == nil)
        let initialWarnings = await warningValidator.wrpVpWarnings[""] ?? []
        #expect(initialWarnings.contains { $0.reason == .other })

        let enforcingValidator = WrpVpRegistrationValidator(trustConfig: trustConfig(vp: .enforce))
        let denied = await enforcingValidator.validateCertificate(wrpac: certificate, wrprc: "not-a-token", dcql: dcql)
        guard case .notGranted = denied else {
            Issue.record("Enforce mode should deny malformed WRPRCs")
            return
        }

        let nonAsciiAllowed = await warningValidator.validateCertificate(wrpac: certificate, wrprc: "☃", dcql: dcql)
        guard case .granted(let nonAsciiWarnings) = nonAsciiAllowed else {
            Issue.record("Warning mode should retain malformed non-ASCII WRPRCs as warnings")
            return
        }
        #expect(nonAsciiWarnings[""]?.isEmpty == false)
        let nonAsciiViolations = await warningValidator.wrpVpWarnings[""] ?? []
        #expect(nonAsciiViolations.count == 1)
        #expect(nonAsciiViolations.first?.reason == .invalidCertificate)
    }

    @Test("VCI coverage checks identify uncovered formats and entitlement requirements")
    func vciCoverageAndEntitlements() throws {
        let mdocCoveredId = try CredentialConfigurationIdentifier(value: "mdoc-covered")
        let mdocMissingId = try CredentialConfigurationIdentifier(value: "mdoc-missing")
        let sdJwtCoveredId = try CredentialConfigurationIdentifier(value: "sdjwt-covered")
        let sdJwtMissingId = try CredentialConfigurationIdentifier(value: "sdjwt-missing")
        let mdoc = MsoMdocFormat.CredentialConfiguration(
            format: "mso_mdoc", scope: nil, cryptographicBindingMethodsSupported: [],
            credentialSigningAlgValuesSupported: [], proofTypesSupported: nil,
            credentialMetadata: nil, docType: "pid", policy: nil
        )
        let sdJwt = SdJwtVcFormat.CredentialConfiguration(
            scope: nil, vct: "org.example.pid", cryptographicBindingMethodsSupported: [],
            credentialSigningAlgValuesSupported: [], proofTypesSupported: nil,
            credentialMetadata: nil,
            credentialDefinition: .init(type: "VerifiableCredential", claims: [])
        )
        let offered: [CredentialConfigurationIdentifier: CredentialSupported] = [
            mdocCoveredId: .msoMdoc(mdoc),
            mdocMissingId: .msoMdoc(MsoMdocFormat.CredentialConfiguration(
                format: "mso_mdoc", scope: nil, cryptographicBindingMethodsSupported: [],
                credentialSigningAlgValuesSupported: [], proofTypesSupported: nil,
                credentialMetadata: nil, docType: "unknown", policy: nil
            )),
            sdJwtCoveredId: .sdJwtVc(sdJwt),
            sdJwtMissingId: .sdJwtVc(SdJwtVcFormat.CredentialConfiguration(
                scope: nil, vct: "org.example.unregistered", cryptographicBindingMethodsSupported: [],
                credentialSigningAlgValuesSupported: [], proofTypesSupported: nil,
                credentialMetadata: nil,
                credentialDefinition: .init(type: "VerifiableCredential", claims: [])
            ))
        ]
        let policy = WrpRegistrationPolicy(
            entitlements: [IssuerEntitlements.pid, IssuerEntitlements.pubEaa],
            sub: "LEI-123", credentials: [],
            providesAttestations: [
                .init(format: "mso_mdoc", meta: .init(doctypeValue: "pid"), claim: nil),
                .init(format: "dc+sd-jwt", meta: .init(vctValues: ["org.example.pid"]), claim: nil)
            ]
        )

        var coverageWarnings = [String: [RegistrationPolicyViolation]]()
        WrpVciRegistrationValidator.validateOfferedConfigurations(offered, policy: policy, wrpVciWarnings: &coverageWarnings)
        #expect(coverageWarnings.keys.sorted() == ["mdoc-missing", "sdjwt-missing"])
        #expect(coverageWarnings["mdoc-missing"]?.first?.reason == .credentialNotCovered(credentialId: "mdoc-missing"))

        var entitlementWarnings = [String: [RegistrationPolicyViolation]]()
        WrpVciRegistrationValidator.validateEntitlements(offered, policy: policy, isPid: { $0 == "pid" || $0 == "org.example.pid" }, wrpVciWarnings: &entitlementWarnings)
        #expect(entitlementWarnings[""] == nil)

        let missingEntitlementsPolicy = WrpRegistrationPolicy(sub: "LEI-123", credentials: [])
        WrpVciRegistrationValidator.validateEntitlements(offered, policy: missingEntitlementsPolicy, isPid: { $0 == "pid" }, wrpVciWarnings: &entitlementWarnings)
        #expect(entitlementWarnings[""]?.count == 2)
        #expect(entitlementWarnings[""]?.contains { $0.reason == .entitlementMissing(expected: IssuerEntitlements.pid) } == true)
        #expect(entitlementWarnings[""]?.contains { $0.reason == .entitlementMissing(expected: [IssuerEntitlements.qeaa, IssuerEntitlements.pubEaa, IssuerEntitlements.nonQEaa].joined(separator: " or ")) } == true)
    }

    @Test("Presentation policy violations map shared validation reasons and retain operation-specific reasons")
    func policyViolationReasonMapping() {
        let mapped: [(RegistrationFailureReason, PresentationFailureReason)] = [
            (.expired, .expired), (.statusRevoked, .statusRevoked), (.statusSuspended, .statusSuspended),
            (.statusApplicationSpecific, .statusApplicationSpecific), (.statusMissing, .statusMissing),
            (.statusRetrievalFailed, .statusRetrievalFailed), (.trustError, .trustError),
            (.invalidType, .invalidType), (.payloadDecodingFailed, .payloadDecodingFailed),
            (.invalidCertificate, .invalidCertificate), (.wrpacDecodingFailed, .wrpacDecodingFailed),
            (.notBoundToAccessCertificate, .notBoundToAccessCertificate),
            (.accessCertificateUnavailable, .accessCertificateUnavailable),
            (.credentialNotCovered(credentialId: "pid"), .other),
            (.entitlementMissing(expected: "role"), .other), (.other, .other)
        ]
        for (registrationReason, expectedReason) in mapped {
            let registration = RegistrationPolicyViolation(reason: registrationReason, message: "detail")
            let presentation = PresentationPolicyViolation(from: registration)
            #expect(presentation.reason == expectedReason)
            #expect(presentation.message == "detail")
        }
    }

    @Test("OpenID4VCI configuration validates clients, registration policy, and proof-of-possession inputs")
    func openId4VciConfigurationBranches() async throws {
        let context = ThreadSafeAuthContext()
        let missingClient = OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example")
        do {
            _ = try await missingClient.toOpenId4VCIConfig(
                credentialIssuerId: "https://issuer.example",
                clientAttestationPopSigningAlgValuesSupported: nil,
                context: context
            )
            Issue.record("A public client without a client id should fail")
        } catch let error as WalletError {
            #expect(error.code == .internalError)
        }

        let registrationAuthorize: RegistrationCertificatePolicy.Authorize = { _, _, _ in .granted(warnings: [:]) }
        let registrationPolicy = RegistrationCertificatePolicy(authorize: registrationAuthorize)
        do {
            _ = try await missingClient.toOpenId4VCIConfig(
                credentialIssuerId: "https://issuer.example",
                clientAttestationPopSigningAlgValuesSupported: nil,
                registrationCertificatePolicy: registrationPolicy,
                context: context
            )
            Issue.record("Registration validation must require signed issuer metadata")
        } catch let error as WalletError {
            #expect(error.code == .invalidWrprc)
        }

        let validClient = OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example", clientId: "wallet-client")
        _ = try await validClient.toOpenId4VCIConfig(
            credentialIssuerId: "https://issuer.example",
            clientAttestationPopSigningAlgValuesSupported: nil,
            context: context
        )

        let signedConfig = OpenId4VciConfiguration(
            credentialIssuerURL: "https://issuer.example",
            clientId: "wallet-client",
            issuerMetadataPolicy: trustConfig().issuerMetadataPolicy
        )
        _ = try await signedConfig.toOpenId4VCIConfig(
            credentialIssuerId: "https://issuer.example",
            clientAttestationPopSigningAlgValuesSupported: nil,
            registrationCertificatePolicy: registrationPolicy,
            context: context
        )

        #expect(try await validClient.makePoPConstructor(
            popUsage: .dpop,
            privateKeyId: "coverage-empty-algs",
            algorithms: [],
            keyOptions: nil,
            context: context
        ) == nil)
        #expect(try await validClient.makePoPConstructor(
            popUsage: .dpop,
            privateKeyId: "coverage-nil-algs",
            algorithms: nil,
            keyOptions: nil,
            context: context
        ) == nil)

        do {
            _ = try await validClient.makePoPConstructor(
                popUsage: .dpop,
                privateKeyId: "coverage-unsupported-alg",
                algorithms: [JWSAlgorithm(.HS256)],
                keyOptions: nil,
                context: context
            )
            Issue.record("The wallet should reject DPoP algorithms it does not support")
        } catch let error as WalletError {
            #expect(error.code == .unsupportedAlgorithm)
        }

        let secureArea = SoftwareSecureArea.create(storage: InMemorySecureKeyStorage())
        SecureAreaRegistry.shared.register(secureArea: secureArea)
        do {
            _ = try await validClient.makePoPConstructor(
                popUsage: .dpop,
                privateKeyId: "coverage-incompatible-curve",
                algorithms: [JWSAlgorithm(.HS256)],
                keyOptions: KeyOptions(curve: .P256, secureAreaName: SoftwareSecureArea.name),
                context: context
            )
            Issue.record("The wallet should reject a curve whose signing algorithm is unsupported by the issuer")
        } catch let error as WalletError {
            #expect(error.code == .unsupportedAlgorithm)
        }

        let popConstructor = try await validClient.makePoPConstructor(
            popUsage: .dpop,
            privateKeyId: "coverage-software-pop-\(UUID().uuidString)",
            algorithms: [JWSAlgorithm(.ES256)],
            keyOptions: KeyOptions(curve: .P256, secureAreaName: SoftwareSecureArea.name),
            context: context
        )
        #expect(popConstructor?.algorithm == JWSAlgorithm(.ES256))

        let clientKeyId = OpenId4VciConfiguration.generatePopKeyId(popUsage: .clientAttestation, credentialIssuerId: "https://issuer.example")
        let dpopKeyId = OpenId4VciConfiguration.generatePopKeyId(popUsage: .dpop, credentialIssuerId: "https://issuer.example")
        #expect(clientKeyId == OpenId4VciConfiguration.generatePopKeyId(popUsage: .clientAttestation, credentialIssuerId: "https://issuer.example"))
        #expect(clientKeyId.hasPrefix("client-attestation-"))
        #expect(dpopKeyId.hasPrefix("dpop-"))
        #expect(clientKeyId != dpopKeyId)
    }
}
