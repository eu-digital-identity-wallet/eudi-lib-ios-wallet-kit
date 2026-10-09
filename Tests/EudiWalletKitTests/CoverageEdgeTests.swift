import Foundation
import Logging
import MdocDataModel18013
import MdocSecurity18013
import JOSESwift
import Testing
import WalletStorage
import X509
@testable import EudiWalletKit

@Suite("Coverage edge paths")
struct CoverageEdgeTests {
    @Test("File logging appends messages and merges event metadata over handler metadata")
    func fileLoggingWritesAndMergesMetadata() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("wallet-log-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: url) }

        var handler = try FileLogHandler(label: "coverage", localFile: url)
        handler.logLevel = .trace
        handler[metadataKey: "source"] = .string("handler")
        handler.log(event: LogEvent(
            level: .info,
            message: "first entry",
            metadata: nil,
            source: "tests",
            file: #fileID,
            function: #function,
            line: #line
        ))
        handler.log(event: LogEvent(
            level: .warning,
            message: "second entry",
            metadata: ["source": .string("event"), "request": .string("123")],
            source: "tests",
            file: #fileID,
            function: #function,
            line: #line
        ))

        let output = try String(contentsOf: url, encoding: .utf8)
        #expect(output.contains("source=handler"))
        #expect(output.contains("first entry"))
        #expect(output.contains("source=event"))
        #expect(output.contains("request=123"))
        #expect(output.contains("second entry"))
        #expect(output.split(separator: "\n").count == 2)
    }

    @Test("File logging reports an unavailable path")
    func fileLoggingRejectsUnavailablePath() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("missing.log")
        do {
            _ = try FileLogging(to: url)
            Issue.record("Opening a file in a missing directory should fail")
        } catch FileHandlerOutputStream.FileHandlerOutputStream.couldNotCreateFile {
            #expect(Bool(true))
        } catch {
            Issue.record("Unexpected file logging error: \(error)")
        }
    }

    @Test("Issuer response associates warnings with matching document metadata")
    func issuerResponseMapsWarningsByConfiguration() throws {
        let warning = RegistrationPolicyViolation(reason: .credentialNotCovered(credentialId: "pid"), message: "not covered")
        let metadata = DocMetadata(
            credentialIssuerIdentifier: "https://issuer.example",
            configurationIdentifier: "pid",
            docType: "eu.example.pid",
            display: nil,
            issuerDisplay: nil,
            claims: nil,
            authorizedRequestData: nil,
            keyOptions: nil,
            credentialOptions: nil
        )
        let document = WalletStorage.Document(
            id: "covered-document",
            docType: "eu.example.pid",
            docDataFormat: .cbor,
            data: Data(),
            docKeyInfo: nil,
            createdAt: .now,
            metadata: metadata.toData(),
            displayName: nil,
            status: .issued
        )
        let noMetadata = WalletStorage.Document(
            id: "without-metadata",
            docType: "other",
            docDataFormat: .cbor,
            data: Data(),
            docKeyInfo: nil,
            createdAt: .now,
            metadata: nil,
            displayName: nil,
            status: .issued
        )
        let response = IssuerResponse(
            documents: [document, noMetadata],
            wrpIssuerWarnings: ["pid": [warning], "other": [], "": [warning]]
        )

        #expect(response.documentWarnings[document.id] == [warning])
        #expect(response.documentWarnings[noMetadata.id] == nil)
        #expect(response.documentWarnings.count == 1)
    }

    @Test("Status checks reject malformed status-list URLs")
    func documentStatusRejectsInvalidReference() async {
        let service = DocumentStatusService(
            statusList: MdocDataModel18013.StatusList(idx: 2, uri: "http://["),
            date: Date(timeIntervalSince1970: 0),
            trustConfig: trustConfig()
        )
        do {
            _ = try await service.getStatus()
            Issue.record("Malformed status-list URLs should be rejected")
        } catch let error as WalletError {
            #expect(error.code == .invalidStatusToken)
        } catch {
            Issue.record("Expected an invalid status token error, received \(error)")
        }
    }

    @Test("Status checks map rejected URL schemes into wallet status errors")
    func documentStatusMapsFetchFailures() async {
        let service = DocumentStatusService(
            statusList: MdocDataModel18013.StatusList(idx: 2, uri: "ftp://status.example/list"),
            date: Date(timeIntervalSince1970: 0),
            trustConfig: trustConfig()
        )
        do {
            _ = try await service.getStatus()
            Issue.record("Status lists must use an accepted URL scheme")
        } catch let error as WalletError {
            #expect(error.code == .statusCheckFailed)
            #expect(error.innerError != nil)
        } catch {
            Issue.record("Expected a status check error, received \(error)")
        }
    }

    @Test("WRP registration binding checks certificate subject identifiers")
    func registrationBindingMatchesSubjectIdentifiers() throws {
        let certificateData = try #require(Data(name: "pidissuerca02_ut", ext: "der", from: Bundle.module))
        let certificate = try Certificate(derEncoded: [UInt8](certificateData))
        let unbound = WrpRegistrationPolicy(sub: "org.example", credentials: [])
        #expect(!unbound.isBound(to: nil))
        #expect(!unbound.isBound(to: certificate))

        let delegated = WrpRegistrationPolicy(
            sub: "org.example",
            credentials: [],
            intermediary: PolicyIntermediary(identifier: "intermediary.example")
        )
        #expect(!delegated.isBound(to: certificate))
    }

    @Test("Status-token signature verification rejects malformed token bytes")
    func rejectsMalformedStatusToken() async {
        let verifier = StatusListTokenSignatureVerifier(trustConfig: trustConfig())
        do {
            try await verifier.verify(statusListToken: Data(), format: .jwt, at: Date(timeIntervalSince1970: 0))
            Issue.record("Malformed status tokens should not verify")
        } catch {
            #expect(Bool(true))
        }
    }

    @Test("Secure-area signature algorithms map supported curves and reject JOSE EdDSA")
    func secureAreaSignatureAlgorithmMapping() throws {
        #expect(try SecureAreaSigner.getSignatureAlgorithm(.ES256) == .ES256)
        #expect(try SecureAreaSigner.getSignatureAlgorithm(.ES384) == .ES384)
        #expect(try SecureAreaSigner.getSignatureAlgorithm(.ES512) == .ES512)
        #expect(try SecureAreaSigner.getSigningAlgorithm(.EDDSA) == .EdDSA)
        #expect(throws: WalletError.self) { try SecureAreaSigner.getSignatureAlgorithm(.EDDSA) }
        #expect(throws: WalletError.self) { try SecureAreaSigner.getSignatureAlgorithm(.UNSET) }
        #expect(throws: WalletError.self) { try SecureAreaSigner.getSigningAlgorithm(.UNSET) }
    }

    @Test("Secure-area signer signs both raw inputs and JOSE header-payload inputs")
    func secureAreaSignerSignsInputs() async throws {
        let area = SoftwareSecureArea.create(storage: InMemorySecureKeyStorage())
        let id = "coverage-signer-\(UUID().uuidString)"
        _ = try await area.createKeyBatch(
            id: id,
            credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1),
            keyOptions: KeyOptions(curve: .P256)
        )
        let coseKey = try await area.getPublicKey(id: id, index: 0, curve: .P256)
        let publicKey = try ECPublicKey(publicKey: coseKey.toSecKey(), additionalParameters: [:])
        let signer = try SecureAreaSigner(
            secureArea: area,
            id: id,
            index: 0,
            publicKey: publicKey,
            curve: .P256,
            ecAlgorithm: .ES256,
            unlockData: nil,
            context: ThreadSafeAuthContext()
        )

        let rawSignature = try await signer.sign(Data("raw input".utf8))
        let jwtSignature = try await signer.signAsync(Data("header".utf8), Data("payload".utf8))
        #expect(rawSignature.count == 64)
        #expect(jwtSignature.count == 64)
        #expect(signer.algorithm == .ES256)
    }

    private func trustConfig() -> TrustConfiguration {
        #if canImport(EudiEtsi1196x2)
        TrustConfiguration(trustSource: .etsi(.eudiRef), defaultPolicy: .warning)
        #else
        TrustConfiguration(rootIaca: [], defaultPolicy: .warning)
        #endif
    }
}
