import CryptoKit
import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import MdocSecurity18013
import OpenID4VP
import protocol OpenID4VP.Networking
import SwiftASN1
import Testing
import X509
@testable import EudiWalletKit

@Suite("OpenID4VP request authentication")
struct OpenId4VpAuthenticationTests {
    private static let responseURI = "https://verifier.example/response"
    private static let requestURI = "https://verifier.example/request"
    private static let docType = "org.iso.18013.5.1.mDL"

    @Test("X.509 requests require the wallet's trust validation result")
    func rejectsMissingTrustEvaluation() async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            for registration in [RegistrationMode.disabled, .warning] {
                let token = try fixture.token(clientId: clientId, validSignature: true, invalidRegistration: registration == .warning)
                let (service, network) = try await makeService(clientId: clientId, token: token,
                    anchors: [fixture.der], registration: registration)
                // Simulate dependency success without the wallet's trust evaluation.
                service.chainVerifier = { _ in true }
				await assertRejected(service, network: network, reportedError: "invalid_client")
                #expect(service.readerAuthenticationStatus == .failed)
                #expect(service.readerCertificateValidationMessage != nil)
                if registration == .warning { #expect(service.wrpVerifierWarnings?.isEmpty == false) }
            }
        }
    }

    @Test("Reader warning policy allows signed requests without claiming certificate trust", arguments: [false, true])
    @MainActor func acceptsReaderTrustWarning(trusted: Bool) async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                anchors: trusted ? [fixture.der] : [], readerTrustPolicy: .warning)
            let requests = try await service.receiveRequest()
            let session = try makeSession(service)
            try session.decodeRequest(requests)
            let expected: ReaderAuthenticationStatus = trusted ? .authenticated : .authenticatedWithUntrustedCertificate
            #expect(service.readerAuthenticationStatus == expected)
            #expect(session.readerAuthenticationStatus == expected)
            #expect(service.readerAuthValidated == trusted)
            #expect(requests[0].defaultReaderAuthResult?.isValidated == trusted)
            #expect((session.readerCertValidationMessage != nil) == !trusted)
            if !trusted { #expect(session.readerLegalName == nil) }
            // Reaching the deliberately failing transport proves both send guards accept the policy.
            await #expect(throws: PostError.self) {
                try await session.sendResponse(userAccepted: false, itemsToSend: [:])
            }
            #expect(await network.posts == 1)
        }
    }

    @Test("Reader warning policy cannot bypass signature verification")
    func rejectsInvalidSignatureWithReaderWarning() async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: false)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                readerTrustPolicy: .warning)
            await assertRejected(service, network: network)
            #expect(service.readerAuthenticationStatus == .failed)
        }
    }

    @Test("Reader warning policy still requires a well-formed evaluated certificate chain")
    func rejectsMissingOrMalformedEvaluationWithReaderWarning() async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                readerTrustPolicy: .warning)
            let validate = service.chainVerifier
            let malformedChains = [[], ["invalid-base64"], [Data([0]).base64EncodedString()],
                [fixture.der.base64EncodedString(), Data([0]).base64EncodedString()]]
            for chain in malformedChains {
                #expect(await validate([fixture.der.base64EncodedString()]))
                #expect(await !validate(chain)) // A prior policy acceptance must not survive malformed input.
            }
            // A dependency reporting success without invoking wallet validation must still be rejected.
            service.chainVerifier = { _ in true }
			await assertRejected(service, network: network, reportedError: "invalid_client")
        }
    }

    @Test("Reader warning policy acceptance is bound to the evaluated leaf certificate")
    func rejectsMismatchedCertificateWithReaderWarning() async throws {
        let fixture = try CertificateFixture()
        let other = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                readerTrustPolicy: .warning)
            let validate = service.chainVerifier
            service.chainVerifier = { _ in await validate([other.der.base64EncodedString()]) }
			await assertRejected(service, network: network, reportedError: "invalid_client")
        }
    }

    @Test("Issuer warning policy does not relax reader certificate trust")
    func keepsIssuerAndReaderPoliciesSeparate() async throws {
        let fixture = try CertificateFixture()
        let clientId = fixture.clientIds[0]
        let token = try fixture.token(clientId: clientId, validSignature: true)
        let (service, network) = try await makeService(clientId: clientId, token: token,
            defaultPolicy: .warning)
        await assertRejected(service, network: network)
        #expect(service.readerAuthenticationStatus == .failed)
    }

    @Test("A failed subsequent request cannot reuse consent or authentication")
    @MainActor func clearsPreviousRequest() async throws {
        let fixture = try CertificateFixture()
        let token = try fixture.token(clientId: fixture.clientIds[0], validSignature: true)
        let (service, network) = try await makeService(clientId: fixture.clientIds[0], token: token, byReference: true, anchors: [fixture.der])
        let requests = try await service.receiveRequest()
        let session = try makeSession(service)
        try session.decodeRequest(requests)
        #expect(session.readerAuthenticationStatus == .authenticated)
        #expect(!session.disclosedDocumentSets.isEmpty)

        await network.setToken(try fixture.token(clientId: "unknown:verifier.example", validSignature: true))
        #expect(await session.receiveRequest() == nil)
        #expect(session.status == .error)
        #expect(session.readerAuthenticationStatus == .failed)
        #expect(session.readerLegalName == nil)
        #expect(session.readerCertIssuer == nil)
        #expect(session.disclosedDocumentSets.isEmpty)
        #expect(!service.readerAuthValidated)
        #expect(service.certificateChain == nil)
        #expect(service.resolvedRequestData == nil)
        #expect(service.dcql == nil)
        await #expect(throws: WalletError.self) {
            try await service.sendResponse(userAccepted: true, itemsToSend: [:],
                authenticationContext: ThreadSafeAuthContext(), onSuccess: nil)
        }
        #expect(await network.posts == 0)
    }

    @Test("Session publishes validation failure even without an issuer name")
    @MainActor func exposesIssuerlessFailure() async throws {
        let (service, _) = try await makeService(clientId: "redirect_uri:\(Self.responseURI)", token: nil)
        var requests = try await service.receiveRequest()
        let session = try makeSession(service)
        session.presentationService = FaultPresentationService(msg: "Test service")
        requests[0].readerAuthResults = ["": ReaderAuthenticationResult(isValidated: false,
            validationMessage: "Reader authentication was not evaluated", legalName: "Unverified name")]
        try session.decodeRequest(requests)
        #expect(session.readerCertValidationMessage == "Reader authentication was not evaluated")
        #expect(session.readerAuthenticationStatus == .notEvaluated)
        #expect(session.readerLegalName == nil)

        requests[0].readerAuthResults = [:]
        try session.decodeRequest(requests)
        #expect(session.readerAuthenticationStatus == .notEvaluated)
        #expect(session.readerCertValidationMessage == nil)
    }

    @Test("Registration warnings remain separate from successful reader authentication")
    @MainActor func preservesRegistrationWarnings() async throws {
        let fixture = try CertificateFixture()
        let token = try fixture.token(clientId: fixture.clientIds[0], validSignature: true, invalidRegistration: true)
        let (service, network) = try await makeService(clientId: fixture.clientIds[0], token: token,
            anchors: [fixture.der], registration: .warning)
        let requests = try await service.receiveRequest()
        let session = try makeSession(service)
        try session.decodeRequest(requests)
        #expect(session.readerAuthenticationStatus == .authenticated)
        #expect(session.readerLegalName != nil)
        #expect(session.wrpVerifierWarnings?.isEmpty == false)
        await #expect(throws: PostError.self) {
            try await session.sendResponse(userAccepted: false, itemsToSend: [:])
        }
        #expect(await network.posts == 1)
    }

    @Test("A session that cannot decode a request cannot send a response")
    @MainActor func rejectsSendingAfterSessionFailure() async throws {
        let fixture = try CertificateFixture()
        let token = try fixture.token(clientId: fixture.clientIds[0], validSignature: true)
        let (service, network) = try await makeService(clientId: fixture.clientIds[0], token: token, anchors: [fixture.der])
        let session = PresentationSession(presentationService: service, docIdToPresentInfo: [:],
            documentKeyIndexes: [:], userAuthenticationRequired: false, localAuthenticationContext: ThreadSafeAuthContext())
        #expect(await session.receiveRequest() == nil)
        #expect(session.readerAuthenticationStatus == .failed)
        await #expect(throws: WalletError.self) {
            try await session.sendResponse(userAccepted: true, itemsToSend: [:])
        }
        #expect(await network.posts == 0)
    }

    @Test("Session authentication covers every document's reader authentication")
    @MainActor func rejectsPartialAuthenticationVerdict() async throws {
        let (service, _) = try await makeService(clientId: "redirect_uri:\(Self.responseURI)", token: nil)
        var requests = try await service.receiveRequest()
        let session = try makeSession(service)
        session.presentationService = FaultPresentationService(msg: "Test service")
        let invalid = ReaderAuthenticationResult(isValidated: false, validationMessage: "Invalid signature", authBytes: Data([0]))
        var results = ["first-document": invalid, "second-document": invalid]
        // Keep the first/default entry valid: the other document must still affect the verdict.
        results[try #require(results.keys.first)] = ReaderAuthenticationResult(isValidated: true, legalName: "Verified name")
        requests[0].readerAuthResults = results
        #expect(requests[0].defaultReaderAuthResult?.isValidated == true)
        try session.decodeRequest(requests)
        #expect(session.readerAuthenticationStatus == .failed)
        #expect(session.readerLegalName == nil)

        requests[0].readerAuthResults = ["first-document": .init(isValidated: false,
            validationMessage: "Reader authentication not present in request")]
        try session.decodeRequest(requests)
        #expect(session.readerAuthenticationStatus == .notEvaluated)
    }

    @MainActor private func makeSession(_ service: OpenId4VpService) throws -> PresentationSession {
        let document = try #require(service.docsCbor["mdl"])
        let info = DocPresentInfo(docType: Self.docType, secureAreaName: nil, docDataFormat: .cbor,
            displayName: "Driving licence", docClaims: [], typedData: .msoMdoc(document))
        return PresentationSession(presentationService: service, docIdToPresentInfo: ["mdl": info],
            documentKeyIndexes: [:], userAuthenticationRequired: false, localAuthenticationContext: ThreadSafeAuthContext())
    }

    @Test("Request validation cannot overlap another receive or a send")
    func rejectsOverlappingOperations() async throws {
        let fixture = try CertificateFixture()
        let token = try fixture.token(clientId: fixture.clientIds[0], validSignature: true)
        let (service, network) = try await makeService(clientId: fixture.clientIds[0], token: token,
            byReference: true, anchors: [fixture.der])
        _ = try await service.receiveRequest()
        await network.holdNextFetch()
        let receiving = Task { try await service.receiveRequest() }
        await network.waitForHeldFetch()
        #expect(service.readerAuthenticationStatus == .notEvaluated)
        await #expect(throws: WalletError.self) { try await service.receiveRequest() }
        await #expect(throws: WalletError.self) {
            try await service.sendResponse(userAccepted: true, itemsToSend: [:],
                authenticationContext: ThreadSafeAuthContext(), onSuccess: nil)
        }
        #expect(await network.posts == 0)
        await network.resumeFetch()
        #expect(try await !receiving.value.isEmpty)
        #expect(service.readerAuthenticationStatus == .authenticated)
    }

    @Test("Malformed trust input clears previous certificate success")
    func rejectsMalformedTrustInput() async throws {
        let fixture = try CertificateFixture()
        let (service, _) = try await makeService(clientId: fixture.clientIds[0], token: nil, anchors: [fixture.der])
        for malformed in [[], ["!"], [Data([0]).base64EncodedString()]] as [[String]] {
            #expect(await service.chainVerifier([fixture.der.base64EncodedString()]))
            #expect(await !service.chainVerifier(malformed))
            #expect(!service.readerAuthValidated)
            #expect(service.readerCertificateIssuer == nil)
            #expect(service.certificateChain == nil)
            #expect(service.readerCertificateValidationMessage != nil)
        }
    }

    @Test("Unsupported IDs cannot fall back to a preregistered client", arguments: [false, true])
    func rejectsPreregisteredFallback(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        let registered = try fixture.preregistered(clientId: "registered-verifier")
        for clientId in ["unknown:verifier.example", "unregistered-verifier", "openid_federation:verifier.example",
                         "verifier_attestation:verifier.example", "x509_san_dns:verifier.example"] {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                byReference: byReference, clientIdSchemes: [.preregistered([registered]), .redirectUri])
            await assertRejected(service, network: network)
            #expect(await network.fetches == 0)
        }
    }

    @Test("Empty and malformed client IDs are rejected before fetching", arguments: [false, true])
    func rejectsMalformedClientIds(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        for schemes in [nil, [.preregistered([try fixture.preregistered(clientId: "registered")])]] as [[ClientIdScheme]?] {
            for clientId in ["", ":", "x509_san_dns:", "x509_hash:",
                             ":x509_san_dns:verifier.example", "::\(fixture.clientIds[1])"] {
                let token = try fixture.token(clientId: clientId, validSignature: true)
                let (service, network) = try await makeService(clientId: clientId, token: token,
                    byReference: byReference, anchors: [fixture.der], clientIdSchemes: schemes)
                await assertRejected(service, network: network)
                #expect(await network.fetches == 0)
            }
        }
    }

    @Test("Plain redirect requests cannot normalize a malformed prefix")
    func rejectsMalformedPlainRedirectIds() async throws {
        for clientId in [":redirect_uri:\(Self.responseURI)", "::redirect_uri:\(Self.responseURI)"] {
            let (service, network) = try await makeService(clientId: clientId, token: nil)
            await assertRejected(service, network: network)
        }
    }

    @Test("A JWT cannot switch the selected client or scheme", arguments: [false, true])
    func rejectsPayloadClientIdChange(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        let client = try fixture.preregistered(clientId: "registered")
        for payloadId in ["other-client", "custom:other-client", "x509_san_dns:verifier.example"] {
            let token = try fixture.token(clientId: payloadId, validSignature: true)
            let (service, network) = try await makeService(clientId: client.clientId, token: token,
                byReference: byReference, clientIdSchemes: [.preregistered([client]), .x509SanDns])
            await assertRejected(service, network: network)
        }
    }

    @Test("Explicitly registered URI IDs and later registration groups remain supported")
    func acceptsRegisteredUriIds() async throws {
        let fixture = try CertificateFixture()
        let first = try fixture.preregistered(clientId: "first")
        for clientId in ["https://verifier.example/registered", "did:web:verifier.example"] {
            let client = try fixture.preregistered(clientId: clientId)
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, _) = try await makeService(clientId: clientId, token: token,
                clientIdSchemes: [.preregistered([first]), .preregistered([client])])
            #expect(try await !service.receiveRequest().isEmpty)
            #expect(service.resolvedRequestData?.client.id.clientId == clientId)
        }
    }

    @Test("Ambiguous registrations do not select an arbitrary identity")
    func rejectsDuplicateRegistrations() async throws {
        let first = try CertificateFixture()
        let second = try CertificateFixture()
        let clientId = "registered"
        let clients = [try first.preregistered(clientId: clientId), try second.preregistered(clientId: clientId)]
        let token = try first.token(clientId: clientId, validSignature: true)
        let (service, network) = try await makeService(clientId: clientId, token: token,
            clientIdSchemes: clients.map { .preregistered([$0]) })
        await assertRejected(service, network: network)
    }

    @Test("The preregistered convenience initializer defaults to RS256")
    func defaultsToRS256() throws {
        let client = PreregisteredClient(clientId: "registered", verifierLegalName: "Registered verifier",
            webKeys: try WebKeySet(["keys": []]))
        #expect(client.jarSigningAlg.name == "RS256")
    }

    @Test("The configured request algorithm is enforced", arguments: [false, true])
    func rejectsDifferentRegisteredAlgorithm(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        let configured = try fixture.preregistered(clientId: "registered")
        guard case .passByValue(let keys) = configured.jwkSetSource else {
            Issue.record("Expected inline keys")
            return
        }
        let client = PreregisteredClient(clientId: configured.clientId, verifierLegalName: configured.legalName,
            webKeys: keys, jarSigningAlg: JWSAlgorithm(.ES384))
        let token = try fixture.token(clientId: client.clientId, validSignature: true)
        let (service, network) = try await makeService(clientId: client.clientId, token: token,
            byReference: byReference, clientIdSchemes: [.preregistered([client])])
        await assertRejected(service, network: network)
    }

    @Test("Preregistered requests use the exact registered identity and key", arguments: [false, true])
    func selectsRegisteredClient(byReference: Bool) async throws {
        let first = try CertificateFixture()
        let second = try CertificateFixture()
        // Unknown prefixes are legitimate preregistered IDs when explicitly configured.
        let clients = [try first.preregistered(clientId: "registered-verifier"),
                       try second.preregistered(clientId: "custom:registered-verifier")]
        for (fixture, client) in [(first, clients[0]), (second, clients[1])] {
            let token = try fixture.token(clientId: client.clientId, validSignature: true)
            let (service, _) = try await makeService(clientId: client.clientId, token: token,
                byReference: byReference, clientIdSchemes: [.x509SanDns, .preregistered(clients), .redirectUri])
            let requests = try await service.receiveRequest()
            #expect(!requests.isEmpty)
            #expect(service.resolvedRequestData?.client.id.clientId == client.clientId)
            #expect(service.resolvedRequestData?.legalName == client.legalName)
            #expect(service.readerAuthenticationStatus == .authenticated)
            #expect(!service.readerAuthValidated)
        }
        let wrongKeyToken = try first.token(clientId: clients[1].clientId, validSignature: true)
        let (service, network) = try await makeService(clientId: clients[1].clientId, token: wrongKeyToken,
            byReference: byReference, clientIdSchemes: [.preregistered(clients)])
        await assertRejected(service, network: network)
    }

    @Test("Unprefixed IDs cannot impersonate X.509 clients", arguments: [false, true], [false, true])
    func requiresX509Prefix(byReference: Bool, x509Only: Bool) async throws {
        let fixture = try CertificateFixture()
        let schemes: [ClientIdScheme]? = x509Only ? [.x509SanDns, .x509Hash] : nil
        let bareId = "verifier.example"
        let prefixedId = "x509_san_dns:\(bareId)"

        // Sign both forms with the same trusted key so the prefix is the only
        // semantic difference. Rejection must not depend on a bad signature.
        let bareToken = try fixture.token(clientId: bareId, validSignature: true)
        let (bareService, bareNetwork) = try await makeService(clientId: bareId, token: bareToken,
            byReference: byReference, anchors: [fixture.der], clientIdSchemes: schemes)
        await assertRejected(bareService, network: bareNetwork)
        #expect(!bareService.readerAuthValidated)
        #expect(bareService.readerCertificateIssuer == nil)
        #expect(bareService.certificateChain == nil)
        #expect(bareService.vpClientId == nil)

        let prefixedToken = try fixture.token(clientId: prefixedId, validSignature: true)
        let (prefixedService, _) = try await makeService(clientId: prefixedId, token: prefixedToken,
            byReference: byReference, anchors: [fixture.der], clientIdSchemes: schemes)
        let requests = try await prefixedService.receiveRequest()
        #expect(!requests.isEmpty)
        #expect(prefixedService.resolvedRequestData?.client.id.clientId == prefixedId)
        #expect(prefixedService.vpClientId == prefixedId)
        let authentication = try #require(requests.first?.readerAuthResults[""])
        #expect(authentication.isValidated)
        #expect(authentication.certificateChain == [fixture.der])

        // A recognized prefix must still require a valid request signature.
        let invalidToken = try fixture.token(clientId: prefixedId, validSignature: false)
        let (invalidService, invalidNetwork) = try await makeService(clientId: prefixedId, token: invalidToken,
            byReference: byReference, anchors: [fixture.der], clientIdSchemes: schemes)
        await assertRejected(invalidService, network: invalidNetwork)
        #expect(invalidService.readerAuthValidated)
    }

    @Test("Unsupported client IDs cannot bypass JAR authentication", arguments: [false, true])
    func rejectsFallbackIdentity(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        // URL-valued IDs let the old redirect fallback reach its no-op signature check.
        for clientId in ["verifier.example", Self.responseURI,
                         "openid_federation:\(Self.responseURI)", "verifier_attestation:\(Self.responseURI)"] {
            let token = try fixture.token(clientId: clientId, validSignature: false)
            for registration in [RegistrationMode.disabled, .warning, .enforce] {
                let (service, network) = try await makeService(clientId: clientId, token: token,
                    byReference: byReference, anchors: [fixture.der], registration: registration)
                await assertRejected(service, network: network)
                #expect(service.readerCertificateIssuer == nil)
                #expect(service.certificateChain == nil)
            }
        }
    }

    @Test("An accepted certificate cannot compensate for an invalid JAR signature", arguments: [false, true])
    func rejectsInvalidSignature(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: false)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                byReference: byReference, anchors: [fixture.der])
            await assertRejected(service, network: network)
            // The trust callback succeeded; rejection must still happen before consent.
            #expect(service.readerAuthValidated)
            #expect(service.readerAuthenticationStatus == .failed)
        }
    }

    @Test("A signed request with an untrusted certificate cannot reach consent")
    func rejectsUntrustedCertificate() async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, network) = try await makeService(clientId: clientId, token: token, anchors: [])
            await assertRejected(service, network: network)
            #expect(!service.readerAuthValidated)
        }
    }

	@Test("Signed requests report an unsatisfiable query to the verifier", arguments: [false, true])
	func reportsUnsatisfiableQueryForSignedRequest(byReference: Bool) async throws {
		let fixture = try CertificateFixture()
		for clientId in fixture.clientIds {
			let token = try fixture.token(clientId: clientId, validSignature: true,
										  requestedDocType: "org.example.unknown")
			let (service, network) = try await makeService(clientId: clientId, token: token,
														   byReference: byReference, anchors: [fixture.der])
			await assertRejected(service, network: network, reportedError: "access_denied")
			#expect(service.readerAuthenticationStatus == .failed)
			#expect(service.readerAuthValidated)
		}
	}

	@Test("Preregistered requests report an unsatisfiable query to the verifier", arguments: [false, true])
	func reportsUnsatisfiableQueryForPreregisteredRequest(byReference: Bool) async throws {
		let fixture = try CertificateFixture()
		let client = try fixture.preregistered(clientId: "registered-verifier")
		let token = try fixture.token(
			clientId: client.clientId,
			validSignature: true,
			requestedDocType: "org.example.unknown"
		)
		let (service, network) = try await makeService(
			clientId: client.clientId,
			token: token,
			byReference: byReference,
			clientIdSchemes: [.preregistered([client])]
		)

		await assertRejected(service, network: network, reportedError: "access_denied")
		#expect(service.readerAuthenticationStatus == .failed)
		#expect(!service.readerAuthValidated)
	}

    @Test("Authenticated X.509 requests reach consent with the expected client ID", arguments: [false, true])
    func acceptsSignedRequest(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, _) = try await makeService(clientId: clientId, token: token,
                byReference: byReference, anchors: [fixture.der])
            let requests = try await service.receiveRequest()
            #expect(!requests.isEmpty)
            #expect(service.resolvedRequestData?.client.id.clientId == clientId)
            let authentication = try #require(requests.first?.readerAuthResults[""])
            #expect(authentication.isValidated)
            #expect(authentication.certificateChain == [fixture.der])
        }
    }

    @Test("Plain redirect-URI requests remain supported without a fabricated legal name")
    @MainActor func acceptsPlainRedirect() async throws {
        let (service, network) = try await makeService(clientId: "redirect_uri:\(Self.responseURI)", token: nil)
        #expect(service.readerAuthenticationStatus == .notEvaluated)
        let requests = try await service.receiveRequest()
        #expect(!requests.isEmpty)
        #expect(service.resolvedRequestData?.legalName == nil)
        #expect(!service.readerAuthValidated)
        let session = try makeSession(service)
        try session.decodeRequest(requests)
        #expect(session.readerAuthenticationStatus == .notApplicable)
        #expect(session.readerLegalName == nil)
        // The transport deliberately rejects POSTs; reaching it proves this flow can still respond.
        await #expect(throws: PostError.self) {
            try await session.sendResponse(userAccepted: false, itemsToSend: [:])
        }
        #expect(await network.posts == 1)
    }

	@Test(
		"Preferred response modes preserve consent and require encryption metadata",
		arguments: [false, true], [false, true]
	)
	func validatesPreferredResponseMode(userAccepted: Bool, encrypted: Bool) async throws {
		let (service, network) = try await makeService(clientId: "redirect_uri:\(Self.responseURI)", token: nil)
		_ = try await service.receiveRequest()
		let resolved = try #require(service.resolvedRequestData)

		#expect(resolved.request.state == nil)
		#expect(resolved.request.responseEncryptionSpecification == nil)

		service.openID4VpConfig = .init(preferredResponseMode: encrypted ? .directPostJWT : .directPost)

		let queryId = try QueryId(value: "mdl")
		let consent: ClientConsent = userAccepted
		? .vpToken(
			vpContent: .dcql(
				verifiablePresentations: [
					queryId: [.generic("presentation")]
				]
			)
		)
		: .negative(message: "access_denied")

		if encrypted {
			#expect(throws: WalletError.self) {
				do {
					_ = try service.buildAuthorizationResponse(resolved: resolved, consent: consent)
				} catch let error as WalletError {
					#expect(error.code == .responseEncryptionMissing)
					throw error
				}
			}
		} else {
			let response = try service.buildAuthorizationResponse(resolved: resolved, consent: consent)
			guard case let .directPost(url, payload) = response else {
				Issue.record("Expected a direct POST response")
				return
			}

			#expect(url.absoluteString == Self.responseURI)

			let data = try JSONEncoder().encode(payload)
			let fields = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
			#expect(fields["state"] as? String == "")

			if userAccepted {
				let presentations = try #require(fields["vp_token"] as? [String: [String]])
				#expect(presentations == ["mdl": ["presentation"]])
				#expect(fields["error"] == nil)
			} else {
				#expect(fields["error"] as? String == "access_denied")
				#expect(fields["vp_token"] == nil)
			}
		}
		#expect(await network.posts == 0)
	}

	private func assertRejected(
		_ service: OpenId4VpService,
		network: RequestNetworking,
		reportedError: String? = nil
	) async {
        await #expect(throws: WalletError.self) { try await service.receiveRequest() }
        #expect(service.resolvedRequestData == nil)
        #expect(service.dcql == nil)
        let selected: RequestItems = ["mdl": ["org.iso.18013.5.1": [.init(elementPath: ["family_name"])]]]
        for items in [[:], selected] {
            await #expect(throws: WalletError.self) {
                try await service.sendResponse(userAccepted: true, itemsToSend: items,
                    authenticationContext: ThreadSafeAuthContext(), onSuccess: nil)
            }
        }
		#expect(await network.posts == (reportedError == nil ? 0 : 1))
		if let reportedError { #expect(await network.postBodies.last?.contains("error=\(reportedError)") == true) }
		#expect(await network.postBodies.allSatisfy { !$0.contains("vp_token=") })
        #expect(service.presentedDocumentIds.isEmpty)
    }

    private enum RegistrationMode { case disabled, warning, enforce }

    private func makeService(clientId: String, token: String?, byReference: Bool = false,
                             anchors: [Data] = [], registration: RegistrationMode = .disabled,
                             readerTrustPolicy: TrustPolicy = .enforce, defaultPolicy: TrustPolicy = .enforce,
                             clientIdSchemes: [ClientIdScheme]? = nil) async throws -> (OpenId4VpService, RequestNetworking) {
        let registrationPolicy: TrustPolicy = registration == .warning ? .warning : .enforce
        #if canImport(EudiEtsi1196x2)
        let trust = TrustConfiguration(trustSource: .staticList(.init(rootCertificates: anchors, method: .directTrust)), defaultPolicy: defaultPolicy, readerTrustPolicy: readerTrustPolicy, wrprcVpTrustPolicy: registrationPolicy)
        #else
        let trust = TrustConfiguration(rootIaca: anchors.map { [$0] }, defaultPolicy: defaultPolicy, readerTrustPolicy: readerTrustPolicy, wrprcVpTrustPolicy: registrationPolicy)
        #endif
        let resource = try #require(Bundle.module.url(forResource: "mdoc-mdl", withExtension: "txt"))
        let encoded = try String(contentsOf: resource, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let document = try #require(Data(base64URLEncoded: encoded))
        let parameters = InitializeTransferData(dataFormats: ["mdl": "cbor"], documentData: ["mdl": document],
            documentKeyIndexes: [:], docMetadata: [:], docDisplayNames: [:], docKeyInfos: [:],
            trustValidator: trust.accessTrustManager, deviceAuthMethod: "deviceSignature",
            idsToDocTypes: ["mdl": Self.docType], hashingAlgs: [:], bleTransferMode: .server)
        var url = URLComponents(string: "openid4vp://authorize")!
        if let token {
            url.queryItems = [.init(name: "client_id", value: clientId),
                .init(name: byReference ? "request_uri" : "request", value: byReference ? Self.requestURI : token)]
        } else {
            url.queryItems = try Self.payload(clientId: clientId).map { key, value in
                let text: String
                if let string = value as? String { text = string }
                else { text = String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self) }
                return URLQueryItem(name: key, value: text)
            }
        }
        let network = RequestNetworking(token: token ?? "")
        let service = try await OpenId4VpService(parameters: parameters, qrCode: Data(url.string!.utf8),
            openID4VpConfig: .init(clientIdSchemes: clientIdSchemes, validateRegistrationCertificate: registration != .disabled), networking: network,
            trustConfig: trust, wrpRegistrationValidator: .init(trustConfig: trust))
        return (service, network)
    }

    private static func payload(clientId: String, requestedDocType: String? = nil) -> [String: Any] {
        ["client_id": clientId, "response_type": "vp_token", "response_mode": "direct_post",
         "response_uri": responseURI, "nonce": "authentication-regression-test",
         "dcql_query": ["credentials": [["id": "mdl", "format": "mso_mdoc",
             "meta": ["doctype_value": requestedDocType ?? docType], "claims": [["path": ["org.iso.18013.5.1", "family_name"]]]]]]]
    }

    private struct CertificateFixture {
        let key = P256.Signing.PrivateKey()
        let der: Data
        var clientIds: [String] {
            ["x509_san_dns:verifier.example", "x509_hash:\(Self.base64URL(Data(SHA256.hash(data: der))))"]
        }
        init() throws {
            let name = try DistinguishedName { CommonName("verifier.example"); OrganizationName("Test Verifier") }
            let certificate = try Certificate(version: .v3, serialNumber: .init(bytes: [1]), publicKey: .init(key.publicKey),
                notValidBefore: Date().addingTimeInterval(-3600), notValidAfter: Date().addingTimeInterval(86400),
                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                    KeyUsage(digitalSignature: true, keyCertSign: true)
                    SubjectAlternativeNames([.dnsName("verifier.example")])
                }, issuerPrivateKey: .init(key))
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            der = Data(serializer.serializedBytes)
        }
        func token(clientId: String, validSignature: Bool, invalidRegistration: Bool = false, requestedDocType: String? = nil) throws -> String {
            let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [der.base64EncodedString()]])
            var claims = OpenId4VpAuthenticationTests.payload(clientId: clientId, requestedDocType: requestedDocType)
            if invalidRegistration { claims["verifier_info"] = [["format": "registration_cert", "data": "invalid-registration-certificate"]] }
            let payload = try JSONSerialization.data(withJSONObject: claims)
            let input = "\(Self.base64URL(header)).\(Self.base64URL(payload))"
            let signature = validSignature ? try key.signature(for: Data(input.utf8)).rawRepresentation : Data(repeating: 0, count: 64)
            return "\(input).\(Self.base64URL(signature))"
        }
        func preregistered(clientId: String) throws -> PreregisteredClient {
            let coordinates = key.publicKey.x963Representation.dropFirst()
            let keys = try WebKeySet(["keys": [["kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
                "x": Self.base64URL(Data(coordinates.prefix(32))), "y": Self.base64URL(Data(coordinates.suffix(32)))]]])
            return PreregisteredClient(clientId: clientId, verifierLegalName: "Registered \(clientId)",
                webKeys: keys, jarSigningAlg: JWSAlgorithm(.ES256))
        }
        static func base64URL(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
    }

    private actor RequestNetworking: Networking {
        var token: String
        var posts = 0
		var postBodies: [String] = []
        var fetches = 0
        private var holdFetch = false
        private var heldFetch: CheckedContinuation<Void, Never>?
        private var fetchObserver: CheckedContinuation<Void, Never>?
        init(token: String) { self.token = token }
        func setToken(_ token: String) { self.token = token }
        func holdNextFetch() { holdFetch = true }
        func waitForHeldFetch() async {
            if heldFetch != nil { return }
            await withCheckedContinuation { fetchObserver = $0 }
        }
        func resumeFetch() { heldFetch?.resume(); heldFetch = nil }
        func data(from url: URL) async throws -> (Data, URLResponse) {
            fetches += 1
            if holdFetch {
                holdFetch = false
                await withCheckedContinuation {
                    heldFetch = $0
                    fetchObserver?.resume(); fetchObserver = nil
                }
            }
            #expect(url.absoluteString == OpenId4VpAuthenticationTests.requestURI)
            return (Data(token.utf8), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)
        }
        func data(for request: URLRequest) async throws -> (Data, URLResponse) {
			if request.httpMethod == "POST" {
				posts += 1
				postBodies.append(String(decoding: request.httpBody ?? Data(), as: UTF8.self))
				throw URLError(.unsupportedURL)
			}
            return try await data(from: #require(request.url))
        }
    }
}
