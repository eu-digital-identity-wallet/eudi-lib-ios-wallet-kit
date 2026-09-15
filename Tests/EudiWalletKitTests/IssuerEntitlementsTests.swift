import Testing
@testable import EudiWalletKit

@Suite("Issuer entitlements")
struct IssuerEntitlementsTests {
    @Test("Every EAA role satisfies a non-PID offer", arguments: [
        IssuerEntitlements.qeaa, IssuerEntitlements.pubEaa, IssuerEntitlements.nonQEaa
    ])
    func eaaAlternatives(entitlement: String) {
        let policy = WrpRegistrationPolicy(entitlements: [entitlement], sub: "issuer", credentials: [])
        #expect(policy.findUnmetEntitlements(offered: [.init(doctypeValue: "eaa")], isPid: { _ in false }).isEmpty)
    }

    @Test("Mixed offers require both roles and deduplicate unmet requirements")
    func mixedOffers() {
        let offered: [PolicyCredentialMeta] = [
            .init(doctypeValue: "custom-pid"), .init(vctValues: ["eaa"]), .init()
        ]
        let pidOnly = WrpRegistrationPolicy(entitlements: [IssuerEntitlements.pid], sub: "issuer", credentials: [])
        #expect(pidOnly.findUnmetEntitlements(offered: offered, isPid: { $0 == "custom-pid" }) == [.eaaProvider])
        let eaaOnly = WrpRegistrationPolicy(entitlements: [IssuerEntitlements.qeaa], sub: "issuer", credentials: [])
        #expect(eaaOnly.findUnmetEntitlements(offered: offered, isPid: { $0 == "custom-pid" }) == [.pidProvider])
        let both = WrpRegistrationPolicy(entitlements: [IssuerEntitlements.pid, IssuerEntitlements.nonQEaa], sub: "issuer", credentials: [])
        #expect(both.findUnmetEntitlements(offered: offered, isPid: { $0 == "custom-pid" }).isEmpty)
    }

    @Test("PID classification examines mdoc and every SD-JWT identifier")
    func identifiers() {
        let policy = WrpRegistrationPolicy(sub: "issuer", credentials: [])
        let offered = [PolicyCredentialMeta(vctValues: ["other", "custom-pid"], doctypeValue: "mdoc")]
        #expect(policy.findUnmetEntitlements(offered: offered, isPid: { $0 == "custom-pid" }) == [.pidProvider])
        #expect(policy.findUnmetEntitlements(offered: offered, isPid: { $0 == "mdoc" }) == [.pidProvider])
        #expect(policy.findUnmetEntitlements(offered: offered, isPid: { _ in false }) == [.eaaProvider])
        #expect(policy.findUnmetEntitlements(offered: [.init()], isPid: { _ in true }) == [.eaaProvider])
        #expect(policy.findUnmetEntitlements(offered: [], isPid: { _ in false }).isEmpty)
    }

    @Test("Logging recognizes the case-sensitive non-qualified EAA entitlement")
    func loggedType() {
        let policy = WrpRegistrationPolicy(entitlements: [IssuerEntitlements.nonQEaa], sub: "issuer", credentials: [])
        #expect(IssuerEntitlements.nonQEaa == "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider")
        #expect(TransactionLogUtils.interactingPartyType(policy) == "NonQEAAProvider")
        let incorrectCase = WrpRegistrationPolicy(entitlements: ["https://uri.etsi.org/19475/Entitlement/NON_Q_EAA_Provider"], sub: "issuer", credentials: [])
        #expect(TransactionLogUtils.interactingPartyType(incorrectCase) == nil)
    }
}
