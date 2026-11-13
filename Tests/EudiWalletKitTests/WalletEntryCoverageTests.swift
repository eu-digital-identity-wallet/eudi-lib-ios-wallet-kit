import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import Testing
import WalletStorage
@testable import EudiWalletKit

@Suite("Wallet entry point coverage")
struct WalletEntryCoverageTests {
    @Test("Rejects a service name containing a colon")
    func rejectsInvalidServiceName() throws {
        do {
            _ = try makeWallet(serviceName: "invalid:service")
            Issue.record("A colon in the service name should be rejected")
        } catch let error as WalletError {
            #expect(error.code == .invalidServiceName)
        }
    }

    @Test("Preparation reports that an empty wallet has no presentable documents")
    func preparationWithoutDocuments() async throws {
        let wallet = try makeWallet()

        do {
            _ = try await wallet.prepareServiceDataParameters()
            Issue.record("An empty wallet should not prepare transfer parameters")
        } catch let error as WalletError {
            #expect(error.code == .noDocumentsAvailable)
            #expect(error.localizationKey == "request_data_no_document")
        }
    }

    @Test("Presentation using a supplied service returns an error session when the wallet is empty")
    func suppliedServiceWithoutDocuments() async throws {
        let wallet = try makeWallet()
        let session = await wallet.beginPresentation(
            service: FaultPresentationService(msg: "unused service"),
            sessionTransactionLogger: nil
        )

        #expect(await session.receiveRequest() == nil)
        #expect(session.status == .error)
        #expect(session.uiError?.code == .noDocumentsAvailable)
    }

    @Test("Presentation flow preserves the empty-wallet failure in its session")
    func flowWithoutDocuments() async throws {
        let wallet = try makeWallet()
        let session = await wallet.beginPresentation(flow: .openid4vp(qrCode: Data()))

        #expect(session.presentationService.flow == .other)
        #expect(session.status == .initializing)
        #expect(await session.receiveRequest() == nil)
        #expect(session.status == .error)
        #expect(session.uiError?.code == .noDocumentsAvailable)
    }

    @Test("Fault service propagates its configured error from each operation")
    func faultServiceOperations() async throws {
        let service = FaultPresentationService(msg: "service unavailable")
        let keyOptions = KeyOptions(curve: .P256)

        do {
            _ = try await service.startQrEngagement(secureAreaName: nil, keyOptions: keyOptions)
            Issue.record("QR engagement should propagate the configured failure")
        } catch {
            #expect(error.localizedDescription == "service unavailable")
        }
        do {
            _ = try await service.receiveRequest()
            Issue.record("Request reception should propagate the configured failure")
        } catch {
            #expect(error.localizedDescription == "service unavailable")
        }
        do {
            try await service.sendResponse(userAccepted: false, itemsToSend: [:], deviceNameSpacesToSend: nil, onSuccess: nil)
            Issue.record("Sending a response should propagate the configured failure")
        } catch {
            #expect(error.localizedDescription == "service unavailable")
        }
        do {
            try await service.waitForDisconnect()
            Issue.record("Waiting for disconnect should propagate the configured failure")
        } catch {
            #expect(error.localizedDescription == "service unavailable")
        }
    }

    @Test("Reads and resets a wallet log file in the cache directory")
    func readsAndResetsLogFile() throws {
        let wallet = try makeWallet()
        let fileName = "wallet-log-\(UUID().uuidString).txt"
        let fileURL = try #require(try EudiWallet.getLogFileURL(fileName))
        try Data("test log".utf8).write(to: fileURL)

        #expect(try wallet.getLogFileContents(fileName) == "test log")
        try wallet.resetLogFile(fileName)
        #expect(!FileManager.default.fileExists(atPath: fileURL.path))
    }

    @Test("Runs authorized actions directly when authentication is disabled")
    func authorizedActionWithoutAuthentication() async throws {
        var wasDismissed = false
        let result = try await EudiWallet.authorizedAction(
            action: { "action result" },
            disabled: true,
            dismiss: { wasDismissed = true },
            localizedReason: "test authorization",
            authenticationContext: ThreadSafeAuthContext()
        )

        #expect(result == "action result")
        #expect(!wasDismissed)
    }

    @Test("Propagates failures from authorized actions")
    func authorizedActionFailure() async {
        let failure = NSError(domain: "authorized-action", code: 4, userInfo: [NSLocalizedDescriptionKey: "action failed"])
        do {
            _ = try await EudiWallet.authorizedAction(
                action: { throw failure },
                disabled: true,
                dismiss: {},
                localizedReason: "test authorization",
                authenticationContext: ThreadSafeAuthContext()
            )
            Issue.record("The action failure should be propagated")
        } catch {
            #expect((error as NSError).domain == "authorized-action")
        }
    }

    private func makeWallet(serviceName: String = "wallet-entry-\(UUID().uuidString)") throws -> EudiWallet {
        #if canImport(EudiEtsi1196x2)
        let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef))
        #else
        let trustConfig = TrustConfiguration(rootIaca: [])
        #endif
        return try EudiWallet(
            eudiWalletConfig: EudiWalletConfiguration(serviceName: serviceName),
            trustConfig: trustConfig,
            storageService: EmptyWalletEntryStorage()
        )
    }
}

private actor EmptyWalletEntryStorage: DataStorageService {
    func loadDocument(id: String, status: DocumentStatus) async throws -> WalletStorage.Document? { nil }
    func loadDocumentMetadata(id: String, status: DocumentStatus) async throws -> DocMetadata? { nil }
    func loadDocuments(status: DocumentStatus) async throws -> [WalletStorage.Document]? { [] }
    func saveDocument(_ document: WalletStorage.Document, batch: [WalletStorage.Document]?, allowOverwrite: Bool) async throws {}
    func deleteDocument(id: String, status: DocumentStatus) async throws {}
    func deleteDocuments(status: DocumentStatus) async throws {}
    func deleteDocumentCredential(id: String, index: Int) async throws {}
}
