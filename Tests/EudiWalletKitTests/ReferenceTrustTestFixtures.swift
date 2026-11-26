#if canImport(EudiEtsi1196x2)
import Foundation
import MdocSecurity18013

enum ReferenceTrustTestFixtures {
    static let trustSource: TrustSource = {
        guard let url = Bundle.module.url(forResource: "pidissuerca02_eu", withExtension: "der"),
              let certificate = try? Data(contentsOf: url) else {
            preconditionFailure("Missing the EUDI reference LoTE signer CA test certificate")
        }
        return .etsi(.eudiRef(loteSignerTrustAnchors: [certificate]))
    }()
}
#endif
