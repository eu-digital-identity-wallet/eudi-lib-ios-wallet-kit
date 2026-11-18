#if canImport(EudiEtsi1196x2)
import Foundation
import EudiEtsi1196x2
import MdocSecurity18013
import Testing
import os
@testable import EudiWalletKit

struct StatusTrustContextTests {
    @Test("Status managers reuse LoTE caches across checks and configuration copies", arguments: [false, true])
    func reusesLists(registration: Bool) async throws {
        let certificate = try Data(contentsOf: #require(Bundle.module.url(forResource: "pidissuerca02_ut", withExtension: "der")))
        let loader = StatusListLoader(certificate: certificate)
        let verifier = StatusListVerifier()
        let url = "https://status.example/providers"
        let source = TrustSource.etsi(.init(loteLocations: SupportedLists<NSString>(
            pidProviders: nil, walletProviders: nil, wrpacProviders: nil,
            wrprcProviders: registration ? url as NSString : nil,
            pubEaaProviders: nil, qeaProviders: nil,
            eaaProviders: registration ? [:] : [EudiwIosTrust.shared.mdlUseCase: url as NSString]),
            cacheTtlHours: 24, customJwtSignatureVerifier: verifier, loadLoTE: loader,
            revocationPolicy: .disabled))
        let config = TrustConfiguration(trustSource: source)
        let copy = config
        let owner: StatusListOwner = registration ? .registrationCertificate : .credential(docType: "org.iso.18013.5.1.mDL")
        // No token cache is involved: each call independently asks for certificate validation.
        for configuration in [config, copy, config] {
            let result = await configuration.statusTrustManager(for: owner).validateCertTrustPath(chain: [certificate])
            #expect(!result.0) // An issuance-only list must not authorize a status signer.
        }
        #expect(loader.calls.withLock { $0 } == 1)
        #expect(verifier.calls.withLock { $0 } == 1)
        // Independent configurations must not share validated lists.
        _ = await TrustConfiguration(trustSource: source).statusTrustManager(for: owner).validateCertTrustPath(chain: [certificate])
        #expect(loader.calls.withLock { $0 } == 2)
        #expect(verifier.calls.withLock { $0 } == 2)
    }

    @Test("Concurrent status checks preserve primary and fallback context isolation")
    func concurrentContexts() async throws {
        let certificate = try Data(contentsOf: #require(Bundle.module.url(forResource: "pidissuerca02_ut", withExtension: "der")))
        let primary = TrustSource.staticList(.init(anchorsPerContext: [:],
            contextTypeMappings: ["pid": .pid, "mdl": .pid], revocationPolicy: .disabled))
        let fallback = TrustSource.staticList(.init(anchorsPerContext: [.pidStatus: [certificate]], method: .directTrust,
            contextTypeMappings: ["pid": .pid, "mdl": .mdl], revocationPolicy: .disabled))
        let config = TrustConfiguration(trustSource: primary, fallbackTrustSource: fallback)
        let pid = config.statusTrustManager(for: .credential(docType: "pid"))
        #expect(pid === config.statusTrustManager(for: .credential(docType: "pid")))
        #expect(pid !== config.statusTrustManager(for: .credential(docType: "mdl")))
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<40 {
                group.addTask {
                    let docType = index.isMultiple(of: 2) ? "pid" : "mdl"
                    let manager = config.statusTrustManager(for: .credential(docType: docType))
                    manager.docType = "unknown" // Protocol mutation cannot change the fixed context.
                    let result = await manager.validateCertTrustPath(chain: [certificate])
                    #expect(result.0 == index.isMultiple(of: 2))
                }
            }
        }
        #expect(pid.getVerificationContext() is VerificationContextPIDStatus)
    }

    @Test("Default document mappings select status contexts")
    func defaults() {
        let config = TrustConfiguration(trustSource: .staticList(.init(rootCertificates: [], revocationPolicy: .disabled)))
        for type in ["eu.europa.ec.eudi.pid.1", "urn:eudi:pid:1"] {
            #expect(config.statusTrustManager(for: .credential(docType: type)).getVerificationContext() is VerificationContextPIDStatus)
        }
        let mdl = config.statusTrustManager(for: .credential(docType: "org.iso.18013.5.1.mDL")).getVerificationContext()
        #expect((mdl as? VerificationContextEAAStatus)?.useCase == EudiwIosTrust.shared.mdlUseCase)
        #expect(config.statusTrustManager(for: .registrationCertificate).getVerificationContext() is VerificationContextWalletRelyingPartyRegistrationCertificateStatus)
        #expect(config.statusTrustManager(for: nil).getVerificationContext() == nil)
        #expect(config.statusTrustManager(for: .credential(docType: "unknown")).getVerificationContext() == nil)
    }

    @Test("Custom issuer mappings select status contexts without changing other managers")
    func customMappings() {
        let config = TrustConfiguration(trustSource: .staticList(.init(rootCertificates: [],
            contextTypeMappings: ["custom-pid": .pid, "qualified": .qeaa, "public": .pubEaa], revocationPolicy: .disabled)))
        let pid = config.statusTrustManager(for: .credential(docType: "custom-pid"))
        #expect(pid.getVerificationContext() is VerificationContextPIDStatus)
        #expect(config.statusTrustManager(for: .credential(docType: "qualified")).getVerificationContext() is VerificationContextQEAAStatus)
        #expect(config.statusTrustManager(for: .credential(docType: "public")).getVerificationContext() is VerificationContextPubEAAStatus)
        #expect(config.statusTrustManager(for: .credential(docType: "urn:eudi:pid:1")).getVerificationContext() == nil)
        #expect(config.accessTrustManager.getVerificationContext() is VerificationContextWalletRelyingPartyAccessCertificate)
        #expect(config.registrationTrustManager.getVerificationContext() is VerificationContextWalletRelyingPartyRegistrationCertificate)
        #expect(pid.getVerificationContext() is VerificationContextPIDStatus)
    }

    @Test("Fallback status validation uses fallback mappings and status anchors")
    func fallback() async throws {
        let certificate = try Data(contentsOf: #require(Bundle.module.url(forResource: "pidissuerca02_ut", withExtension: "der")))
        let primary = TrustSource.staticList(.init(anchorsPerContext: [:], contextTypeMappings: [:], revocationPolicy: .disabled))
        let fallback = TrustSource.staticList(.init(anchorsPerContext: [.pidStatus: [certificate]], method: .directTrust,
            contextTypeMappings: ["fallback-pid": .pid], revocationPolicy: .disabled))
        let config = TrustConfiguration(trustSource: primary, fallbackTrustSource: fallback)
        let manager = config.statusTrustManager(for: .credential(docType: "fallback-pid"))
        #expect(await manager.validateCertTrustPath(chain: [certificate]).0)
        #expect(await !config.statusTrustManager(for: .credential(docType: "unknown")).validateCertTrustPath(chain: [certificate]).0)
    }
}
private final class StatusListLoader: IosLoadLoTE, Sendable {
    let certificate: Data

    init(certificate: Data) { self.certificate = certificate }

    let calls = OSAllocatedUnfairLock(initialState: 0)

    func loadLoTE(uri: String) async throws -> any LoadLoTEOutcome {
        calls.withLock { $0 += 1 }
        let formatter = ISO8601DateFormatter()
        let now = Date()
        let payload = try JSONSerialization.data(withJSONObject: ["LoTE": [
            "ListAndSchemeInformation": [
                "LoTEVersionIdentifier": 1, "LoTESequenceNumber": 1,
                "SchemeOperatorName": [["lang": "en", "value": "Test Operator"]],
                "SchemeTerritory": "EU",
                "ListIssueDateTime": formatter.string(from: now),
                "NextUpdate": formatter.string(from: now.addingTimeInterval(86400))
            ], "TrustedEntitiesList": [[
                "TrustedEntityInformation": [
                    "TEName": [["lang": "en", "value": "Test Provider"]],
                    "TEAddress": [
                        "TEPostalAddress": [["lang": "en", "StreetAddress": "1 Test Street", "Country": "EU"]],
                        "TEElectronicAddress": [["lang": "en", "uriValue": "mailto:test@example.test"]]
                    ],
                    "TEInformationURI": [["lang": "en", "uriValue": "https://example.test/info"]]
                ],
                "TrustedEntityServices": [["ServiceInformation": [
                    "ServiceName": [["lang": "en", "value": "Test Issuance"]],
                    "ServiceDigitalIdentity": ["X509Certificates": [["val": certificate.base64EncodedString()]]],
                    "ServiceTypeIdentifier": "http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance"
                ]]]
            ]]
        ]])
        func encode(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let jwt = "\(encode(Data(#"{"alg":"none"}"#.utf8))).\(encode(payload)).signature"
        return LoadLoTEOutcomeLoaded<NSString>(content: jwt as NSString)
    }
}

// Test-only signature acceptance for the locally generated, unsigned LoTE.
private final class StatusListVerifier: VerifyJwtSignature, Sendable {
    let calls = OSAllocatedUnfairLock(initialState: 0)

    func invoke(jwt: String) async throws -> any VerifyJwtSignatureOutcome {
        calls.withLock { $0 += 1 }
        return VerifyJwtSignatureOutcomeVerified(jwt: jwt)
    }
}
#endif
