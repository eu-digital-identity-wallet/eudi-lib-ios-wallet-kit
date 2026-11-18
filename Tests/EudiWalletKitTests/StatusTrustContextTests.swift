#if canImport(EudiEtsi1196x2)
import Foundation
import EudiEtsi1196x2
import MdocSecurity18013
import Testing
@testable import EudiWalletKit

struct StatusTrustContextTests {
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
#endif
