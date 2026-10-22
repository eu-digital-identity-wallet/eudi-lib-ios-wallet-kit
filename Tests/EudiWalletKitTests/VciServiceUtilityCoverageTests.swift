import Foundation
import MdocDataModel18013
import MdocSecurity18013
import OpenID4VCI
import Testing
import WalletStorage
@testable import EudiWalletKit

@Suite("OpenID4VCI service utility coverage")
struct VciServiceUtilityCoverageTests {
    private func loadService(validateRegistrationCertificate: Bool = false) throws -> (OpenId4VciService, CredentialIssuerMetadata) {
        let metadataData = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
        let metadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: metadataData)
        let storageService = TestDataStorageService()
        let trustConfig: TrustConfiguration
        #if canImport(EudiEtsi1196x2)
        trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), defaultPolicy: .warning, wrprcVciTrustPolicy: .warning)
        #else
        trustConfig = TrustConfiguration(rootIaca: [], defaultPolicy: .warning, wrprcVciTrustPolicy: .warning)
        #endif
        let service = try OpenId4VciService(
            uiCulture: "en",
            config: OpenId4VciConfiguration(
                credentialIssuerURL: metadata.credentialIssuerIdentifier.url.absoluteString,
                clientId: "coverage-client",
                requireDpop: false,
                validateRegistrationCertificate: validateRegistrationCertificate
            ),
            networking: TestNetworking(metadata: metadataData),
            storage: StorageManager(storageService: storageService),
            storageService: storageService,
            trustConfig: trustConfig,
            localAuthenticationContext: ThreadSafeAuthContext()
        )
        return (service, metadata)
    }

    @Test("Builds offered models and resolves issuer reuse policies by id and credential type")
    func offeredModelResolution() async throws {
        let (service, metadata) = try loadService()
        let offered = try await service.getCredentialOfferedModels(
            credentialsSupported: metadata.credentialsSupported,
            batchCredentialIssuance: metadata.batchCredentialIssuance
        )
        #expect(offered.count == 4)
        #expect(offered.contains { $0.offered.docType == "eu.europa.ec.eudi.pid.1" })
        #expect(offered.contains { $0.offered.vct == "urn:eudi:pid:de:1" })
        #expect(offered.allSatisfy { $0.offered.credentialOptions.batchSize > 0 })

        #expect(await service.getIssuerReusePolicy(.identifier("pid-mso-mdoc"), credentialsSupported: metadata.credentialsSupported) == nil)
        #expect(await service.getIssuerReusePolicy(.msoMdoc(docType: "eu.europa.ec.eudi.pid.1"), credentialsSupported: metadata.credentialsSupported) == nil)
        #expect(await service.getIssuerReusePolicy(.sdJwt(vct: "urn:eudi:pid:de:1"), credentialsSupported: metadata.credentialsSupported) == nil)
        #expect(await service.getIssuerReusePolicy(.identifier("missing"), credentialsSupported: metadata.credentialsSupported) == nil)
    }

    @Test("Uses supported issuer reuse policy for mDOC and SD-JWT credential identifiers")
    func resolvesIssuerReusePolicies() async throws {
        let (service, _) = try loadService()
        let metadata = try metadataWithReusePolicy()
        let mdoc = try #require(metadata.credentialsSupported.first { $0.key.value == "pid-mso-mdoc" })
        let sdJwt = try #require(metadata.credentialsSupported.first { $0.key.value == "pid-sd-jwt" })

        #expect(await service.getIssuerReusePolicy(.identifier(mdoc.key.value), credentialsSupported: metadata.credentialsSupported)?.id == "arf_annex_ii")
        #expect(await service.getIssuerReusePolicy(.identifier(sdJwt.key.value), credentialsSupported: metadata.credentialsSupported)?.id == "arf_annex_ii")

        let resolved = try await service.getMetadataDefaultCredentialOptions(.identifier("pid-mso-mdoc"), offerMetadata: metadata)
        #expect(resolved.batchSize == 3)
        #expect(resolved.reissueTriggerUnused == 1)
    }

    @Test("Resolves issuer metadata once and reuses its cached value")
    func resolvesAndCachesIssuerMetadata() async throws {
        OpenId4VciService.clearIssuerMetadataCache()
        let (service, expected) = try loadService()

        let first = try await service.getIssuerMetadata()
        let second = try await service.getIssuerMetadata()
        #expect(first.credentialIssuerIdentifier == expected.credentialIssuerIdentifier)
        #expect(second == first)
    }

    @Test("Builds offered issuance details including pre-authorized transaction-code requirements")
    func resolvesCredentialOffer() async throws {
        let (service, metadata) = try loadService()
        let offer = try credentialOffer(metadata: metadata, includesTransactionCode: true)

        let resolved = try await service.resolveOfferDocTypes(offerUri: "coverage-offer", offer: offer)
        #expect(resolved.issuerName == "Bundesdruckerei GmbH")
        #expect(resolved.docModels.count == 4)
        #expect(resolved.isTxCodeRequired)
        #expect(resolved.txCodeSpec?.length == 6)
        #expect(resolved.wrpVciRegistrationPolicy == nil)
        #expect(resolved.wrpVciWarnings == nil)
    }

    @Test("Rejects an offer that cannot be resolved from the issuer response")
    func rejectsMalformedCredentialOfferResponse() async throws {
        let (service, _) = try loadService()
        do {
            _ = try await service.resolveOfferUrlDocTypes(offerUri: "https://issuer.example/offer")
            Issue.record("Issuer metadata is not a credential offer response")
        } catch let error as WalletError {
            #expect(error.code == .offerResolutionFailed)
        }
    }

    @Test("Prepares an issuance request without prompting when authentication is disabled")
    func preparesIssuingRequest() async throws {
        SecureAreaRegistry.shared.register(secureArea: SoftwareSecureArea.create(storage: InMemorySecureKeyStorage()))
        let (service, metadata) = try loadService()
        let offer = try credentialOffer(metadata: metadata)
        let options = CredentialOptions(credentialPolicy: .oneTimeUse, batchSize: 2)

        try await service.prepareIssuing(
            id: "coverage-issue-request",
            docTypeIdentifier: .identifier("pid-mso-mdoc"),
            displayName: "PID",
            credentialOptions: options,
            keyOptions: nil,
            disablePrompt: true,
            promptMessage: nil,
            offer: offer
        )

        #expect(await service.keyBatchSize == 2)
    }

    @Test("Requires the transaction code before authorizing a pre-authorized offer")
    func requiresPreAuthorizedTransactionCode() async throws {
        let (service, metadata) = try loadService()
        let offerUri = "coverage-tx-code-\(UUID().uuidString)"
        let offer = try credentialOffer(metadata: metadata, includesTransactionCode: true)
        let resolved = try await service.resolveOfferDocTypes(offerUri: offerUri, offer: offer)

        do {
            _ = try await service.authorizeOffer(
                offerUri: offerUri,
                docTypeModels: resolved.docModels,
                txCodeValue: nil,
                authorized: nil,
                forceRefreshToken: false
            )
            Issue.record("Offers with a transaction-code requirement should not authorize without one")
        } catch let error as WalletError {
            #expect(error.code == .authorizationFailed)
        }
    }

    @Test("Rejects uncached authorization requests and invalid transaction-id counts")
    func rejectsInvalidIssuanceState() async throws {
        let (service, _) = try loadService()
        do {
            _ = try await service.authorizeOffer(
                offerUri: "missing-offer",
                docTypeModels: [],
                txCodeValue: nil,
                authorized: nil,
                forceRefreshToken: false
            )
            Issue.record("Authorization must require a resolved offer")
        } catch let error as WalletError {
            #expect(error.code == .internalError)
        }

        let noDocuments = try await service.issueDocumentsByOfferUrl(
            offerUri: "missing-offer",
            docTypes: [],
            authorized: nil,
            documentId: nil
        )
        #expect(noDocuments.isEmpty)
        do {
            _ = try await service.issueDocumentsByOfferUrl(
                offerUri: "missing-offer",
                docTypes: [],
                authorized: nil,
                documentId: nil,
                issuanceTransactionIds: ["orphan-id"]
            )
            Issue.record("Transaction ids must match the offered document count")
        } catch let error as WalletError {
            #expect(error.code == .internalError)
        }
    }

    @Test("Registration validation configuration is optional and authorizes through the WRP validator")
    func registrationCertificatePolicyLifecycle() async throws {
        let (disabled, _) = try loadService()
        #expect(await disabled.makeRegistrationCertificatePolicy() == nil)

        let (enabled, _) = try loadService(validateRegistrationCertificate: true)
        guard let enforcement = await enabled.makeRegistrationCertificatePolicy() else {
            Issue.record("Expected configured registration certificate policy")
            return
        }
        let authorization = await enforcement.policy.authorize("invalid-wrpac", "not-a-token", [:])
        guard case .granted(let warnings) = authorization else {
            Issue.record("Warning policy should allow issuance and return typed validation warnings")
            return
        }
        #expect(warnings[""]?.isEmpty == false)
    }

    @Test("Matches issuer URLs after trimming trailing slashes")
    func issuerUrlMatching() async throws {
        let (service, metadata) = try loadService()
        let issuer = metadata.credentialIssuerIdentifier.url.absoluteString
        #expect(await service.hasIssuerUrl(issuer))
        #expect(await service.hasIssuerUrl(issuer + "/"))
        #expect(!(await service.hasIssuerUrl("https://another.example")))
    }

    @Test("Registry and network adapter forward calls and preserve service identity")
    func registryAndNetworkAdapter() async throws {
        let (service, metadata) = try loadService()
        let registry = OpenId4VCIServiceRegistry.shared
        let name = "coverage-\(UUID().uuidString)"
        registry.register(name: name, service: service)
        #expect(registry.get(name: name) != nil)
        #expect(registry.getAllNames().contains(name))
        #expect(registry.getAllServices().contains { $0 === service })
        #expect(await [service].getByIssuerURL(metadata.credentialIssuerIdentifier.url.absoluteString) === service)
        #expect(await registry.getByIssuerURL(issuerURL: metadata.credentialIssuerIdentifier.url.absoluteString) === service)

        let payload = Data("adapter response".utf8)
        let adapter = OpenID4VCINetworking(networking: VciCoverageNetworkAdapter(data: payload))
        let url = try #require(URL(string: "https://issuer.example/resource"))
        let getResponse = try await adapter.data(from: url)
        #expect(getResponse.0 == payload)
        let requestResponse = try await adapter.data(for: URLRequest(url: url))
        #expect(requestResponse.0 == payload)
    }

    @Test("Maps generic authorization failures into wallet errors")
    func mapsAuthorizationFailure() {
        let cause = NSError(domain: "authorization", code: 17, userInfo: [NSLocalizedDescriptionKey: "browser unavailable"])
        let result = WalletError.authRequestFailed(error: cause)
        #expect(result.code == .authorizationFailed)
        #expect(result.description == "Authorization request failed: browser unavailable")
        #expect((result.innerError as? NSError)?.code == 17)
    }

    private func credentialOffer(metadata: CredentialIssuerMetadata, includesTransactionCode: Bool = false) throws -> CredentialOffer {
        let authorizationServerMetadata = AuthorizationServerMetadata(
            issuer: "https://issuer.example",
            authorizationEndpoint: "https://issuer.example/authorize",
            tokenEndpoint: "https://issuer.example/token"
        )
        let grant: Grants? = if includesTransactionCode {
            .preAuthorizedCode(.init(
                preAuthorizedCode: "pre-authorized-code",
                txCode: TxCode(inputMode: .numeric, length: 6, description: "Enter your code")
            ))
        } else {
            nil
        }
        return try CredentialOffer(
            credentialIssuerIdentifier: metadata.credentialIssuerIdentifier,
            credentialIssuerMetadata: metadata,
            credentialConfigurationIdentifiers: Array(metadata.credentialsSupported.keys),
            grants: grant,
            authorizationServerMetadata: .oauth(authorizationServerMetadata)
        )
    }

    private func metadataWithReusePolicy() throws -> CredentialIssuerMetadata {
        let data = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
        var root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var credentials = try #require(root["credential_configurations_supported"] as? [String: Any])
        for identifier in ["pid-mso-mdoc", "pid-sd-jwt"] {
            var configuration = try #require(credentials[identifier] as? [String: Any])
            var credentialMetadata = try #require(configuration["credential_metadata"] as? [String: Any])
            credentialMetadata["credential_reuse_policy"] = [
                "id": "arf_annex_ii",
                "options": [[
                    "details": ["once_only"],
                    "batch_size": 3,
                    "reissue_trigger_unused": 1
                ]]
            ] as [String: Any]
            configuration["credential_metadata"] = credentialMetadata
            credentials[identifier] = configuration
        }
        root["credential_configurations_supported"] = credentials
        let updated = try JSONSerialization.data(withJSONObject: root)
        return try JSONDecoder().decode(CredentialIssuerMetadata.self, from: updated)
    }
}

private struct VciCoverageNetworkAdapter: NetworkingProtocol {
    let data: Data

    func data(from url: URL) async throws -> (Data, URLResponse) {
        (data, HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: [:])!)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(from: request.url ?? URL(string: "https://issuer.example")!)
    }
}
