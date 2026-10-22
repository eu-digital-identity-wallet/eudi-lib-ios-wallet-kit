import Foundation
import MdocDataModel18013
import Testing
import WalletStorage
@testable import EudiWalletKit

@Suite("Storage manager lifecycle coverage")
struct StorageManagerCoverageTests {
    @Test("Loads and removes pending and deferred documents and refreshes published state")
    func loadsAndRemovesDocumentsByStatus() async throws {
        let pending = document(id: "pending-1", status: .pending)
        let deferred = document(id: "deferred-1", status: .deferred)
        let storage = StorageManagerCoverageDataStorage(documents: [pending, deferred])
        let manager = StorageManager(storageService: storage)

        _ = try await manager.loadDocuments(status: .pending, uiCulture: "en")
        _ = try await manager.loadDocuments(status: .deferred, uiCulture: "en")
        let loadedState = await MainActor.run {
            (manager.pendingDocuments.map(\.id), manager.deferredDocuments.map(\.id), manager.hasData, manager.docCount)
        }
        #expect(loadedState.0 == ["pending-1"])
        #expect(loadedState.1 == ["deferred-1"])
        #expect(loadedState.2)
        #expect(loadedState.3 == 0)

        _ = try await manager.loadDocument(id: "pending-1", uiCulture: "en", status: .pending)
        #expect(await MainActor.run { manager.pendingDocuments.count } == 1)
        try await manager.removePendingOrDeferredDoc(id: "pending-1")
        try await manager.removePendingOrDeferredDoc(id: "deferred-1")
        let removedState = await MainActor.run {
            (manager.pendingDocuments.isEmpty, manager.deferredDocuments.isEmpty, manager.hasData)
        }
        #expect(removedState.0)
        #expect(removedState.1)
        #expect(!removedState.2)
        let remainingDeferred = try await storage.loadDocuments(status: .deferred)
        #expect(remainingDeferred?.isEmpty == true)
    }

    @Test("Handles missing records, invalid issuer data, bulk deletion, and empty model queries")
    func missingAndInvalidDocuments() async throws {
        let badIssued = document(id: "invalid-issued", status: .issued)
        let storage = StorageManagerCoverageDataStorage(documents: [badIssued])
        let manager = StorageManager(storageService: storage)

        let loaded = try await manager.loadDocuments(status: .issued, uiCulture: nil)
        #expect(loaded?.count == 1)
        #expect(await MainActor.run { manager.docModels.isEmpty })
        #expect(await MainActor.run { !manager.hasData })
        #expect(StorageManager.toClaimsModel(doc: badIssued, uiCulture: nil) == nil)
        let presentInfo = try await manager.getDocIdsToPresentInfo(documents: [badIssued])
        #expect(presentInfo.isEmpty)
        #expect(manager.getDocumentModel(id: "missing") == nil)
        #expect(manager.getDocumentModels(docType: "missing").isEmpty)
        let missing = try await manager.loadDocument(id: "missing", uiCulture: nil, status: .pending)
        #expect(missing == nil)

        do {
            try await manager.deleteDocument(id: "missing", status: .issued)
            Issue.record("Deleting a missing document should fail")
        } catch let error as WalletError {
            #expect(error.code == .storageError)
        }

        try await manager.deleteDocuments(status: .issued)
        try await manager.deleteDocuments(status: .pending)
        try await manager.deleteDocuments(status: .deferred)
        let remainingIssued = try await storage.loadDocuments(status: .issued)
        #expect(remainingIssued?.isEmpty == true)
        #expect(await MainActor.run { !manager.hasData })
    }

    @Test("Storage failures are surfaced and retained as wallet errors")
    func storageFailureState() async {
        let manager = StorageManager(storageService: StorageManagerCoverageDataStorage(shouldFail: true))
        do {
            _ = try await manager.loadDocuments(status: .issued, uiCulture: nil)
            Issue.record("A storage failure should be propagated")
        } catch {
            #expect((error as? NSError)?.domain == "StorageManagerCoverageDataStorage")
        }
        let storedError = await MainActor.run { manager.uiError }
        #expect(storedError?.code == .storageError)
        #expect(storedError?.innerError != nil)
    }

    private func document(id: String, status: DocumentStatus) -> WalletStorage.Document {
        WalletStorage.Document(id: id, docType: "test", docDataFormat: .cbor, data: Data([0xff]), docKeyInfo: nil,
            createdAt: .now, metadata: nil, displayName: nil, status: status)
    }
}

private actor StorageManagerCoverageDataStorage: DataStorageService {
    private var documents: [WalletStorage.Document]
    private let shouldFail: Bool

    init(documents: [WalletStorage.Document] = [], shouldFail: Bool = false) {
        self.documents = documents
        self.shouldFail = shouldFail
    }

    func loadDocument(id: String, status: DocumentStatus) async throws -> WalletStorage.Document? {
        try failIfRequested()
        return documents.first { $0.id == id && $0.status == status }
    }

    func loadDocumentMetadata(id: String, status: DocumentStatus) async throws -> DocMetadata? {
        try failIfRequested()
        return documents.first { $0.id == id && $0.status == status }.flatMap { DocMetadata(from: $0.metadata) }
    }

    func loadDocuments(status: DocumentStatus) async throws -> [WalletStorage.Document]? {
        try failIfRequested()
        return documents.filter { $0.status == status }
    }

    func saveDocument(_ document: WalletStorage.Document, batch: [WalletStorage.Document]?, allowOverwrite: Bool) async throws {
        try failIfRequested()
        documents.removeAll { $0.id == document.id && $0.status == document.status }
        documents.append(document)
        if let batch { documents.append(contentsOf: batch) }
    }

    func deleteDocument(id: String, status: DocumentStatus) async throws {
        try failIfRequested()
        documents.removeAll { $0.id == id && $0.status == status }
    }

    func deleteDocuments(status: DocumentStatus) async throws {
        try failIfRequested()
        documents.removeAll { $0.status == status }
    }

    func deleteDocumentCredential(id: String, index: Int) async throws {
        try failIfRequested()
    }

    private func failIfRequested() throws {
        if shouldFail {
            throw NSError(domain: "StorageManagerCoverageDataStorage", code: 1, userInfo: [NSLocalizedDescriptionKey: "storage offline"])
        }
    }
}
