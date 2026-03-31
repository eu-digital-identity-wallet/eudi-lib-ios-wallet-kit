/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Testing
@testable import EudiWalletKit
import Foundation
import MdocDataTransfer18013

// TODO: Add tests for PresentationSession:
// - startQrEngagement (BLE authorized / unauthorized scenarios)
// - receiveRequest / disclosedDocuments handling
// - setError state transitions
// - sendResponse / responseSent status

@Suite("PresentationSession tests")
struct PresentationSessionTests {
    // MARK: - WalletError init backward compatibility
    // MARK: - WalletError backward compatibility

    @Test("WalletError init without optional params preserves backward compatibility")
    func testWalletErrorInitBackwardCompat() {
        let error = WalletError(description: "test error")
        #expect(error.description == "test error")
        #expect(error.localizationKey == nil)
        #expect(error.code == nil)
        #expect(error.context.isEmpty)
    }

    @Test("WalletError init with localizationKey only")
    func testWalletErrorInitWithLocalizationKey() {
        let error = WalletError(description: "test", localizationKey: "some_key")
        #expect(error.localizationKey == "some_key")
        #expect(error.code == nil)
    }

    @Test("WalletError init with code only")
    func testWalletErrorInitWithCode() {
        let error = WalletError(description: "test", code: .bleNotAuthorized)
        #expect(error.code == .bleNotAuthorized)
        #expect(error.localizationKey == nil)
    }

    @Test("WalletError init with both localizationKey and code")
    func testWalletErrorInitWithBoth() {
        let error = WalletError(description: "test", localizationKey: "key", code: .noDocumentsAvailable)
        #expect(error.localizationKey == "key")
        #expect(error.code == .noDocumentsAvailable)
        #expect(error.context.isEmpty)
    }

    @Test("WalletError init with claimNotFound code")
    func testWalletErrorInitWithClaimNotFound() {
        let error = WalletError(description: "test", code: .claimNotFound)
        #expect(error.code == .claimNotFound)
        #expect(error.localizationKey == nil)
    }

    @Test("WalletError init with context")
    func testWalletErrorInitWithContext() {
        let error = WalletError(description: "claim missing", code: .claimNotFound, context: ["claimPath": "org.iso.18013.5.1/portrait"])
        #expect(error.code == .claimNotFound)
        #expect(error.context["claimPath"] == "org.iso.18013.5.1/portrait")
    }

    @Test("WalletError init without context defaults to empty")
    func testWalletErrorInitContextDefault() {
        let error = WalletError(description: "test")
        #expect(error.context.isEmpty)
    }

    // MARK: - mapTransferError

    @Test("mapTransferError maps BLE_NOT_AUTHORIZED to .bleNotAuthorized")
    func testMapBleNotAuthorized() {
        let nsError = MdocHelpers.makeError(code: .bleNotAuthorized)
        let result = PresentationSession.mapTransferError(nsError)
        #expect(result == .bleNotAuthorized)
    }

    @Test("mapTransferError maps BLE_NOT_SUPPORTED to .bleNotSupported")
    func testMapBleNotSupported() {
        let nsError = MdocHelpers.makeError(code: .bleNotSupported)
        let result = PresentationSession.mapTransferError(nsError)
        #expect(result == .bleNotSupported)
    }

    @Test("mapTransferError returns nil for unrelated transfer error codes")
    func testMapUnrelatedErrorCode() {
        let nsError = MdocHelpers.makeError(code: .userRejected)
        let result = PresentationSession.mapTransferError(nsError)
        #expect(result == nil)
    }

    @Test("mapTransferError returns nil for non-transfer errors")
    func testMapNonTransferError() {
        let error = NSError(domain: "SomeOtherDomain", code: 999, userInfo: nil)
        let result = PresentationSession.mapTransferError(error)
        #expect(result == nil)
    }

    // MARK: - makeError

    @Test("makeError produces WalletError with code")
    func testMakeErrorWithCode() {
        let error = PresentationSession.makeError(str: "BLE error", code: .bleNotAuthorized)
        #expect(error.code == .bleNotAuthorized)
        #expect(error.description == "BLE error")
    }

    @Test("makeError without code preserves backward compatibility")
    func testMakeErrorWithoutCode() {
        let error = PresentationSession.makeError(str: "generic error")
        #expect(error.code == nil)
        #expect(error.localizationKey == nil)
    }

    @Test("makeError with localizationKey and code")
    func testMakeErrorWithLocalizationKeyAndCode() {
        let error = PresentationSession.makeError(str: "no docs", localizationKey: "request_data_no_document", code: .noDocumentsAvailable)
        #expect(error.code == .noDocumentsAvailable)
        #expect(error.localizationKey == "request_data_no_document")
    }

    // MARK: - IssuingParty

    @Test("IssuingParty stores issuer info")
    func testIssuingParty() {
        let party = TransactionLog.IssuingParty(name: "Test Issuer", identifier: "https://issuer.example.com", logoUrl: "https://issuer.example.com/logo.png")
        #expect(party.name == "Test Issuer")
        #expect(party.identifier == "https://issuer.example.com")
        #expect(party.logoUrl == "https://issuer.example.com/logo.png")
    }

    @Test("IssuingParty with nil logoUrl")
    func testIssuingPartyWithoutLogo() {
        let party = TransactionLog.IssuingParty(name: "Issuer", identifier: "https://issuer.example.com", logoUrl: nil)
        #expect(party.logoUrl == nil)
    }

    // MARK: - IssuanceLogData

    @Test("IssuanceLogData parses from TransactionLog")
    func testIssuanceLogData() {
        let issuingParty = TransactionLog.IssuingParty(name: "Test Issuer", identifier: "https://issuer.example.com", logoUrl: nil)
        let log = TransactionLog(
            timestamp: 1700000000,
            status: .completed,
            issuingParty: issuingParty,
            type: .issuance,
            dataFormat: .cbor
        )
        let data = IssuanceLogData(log)
        #expect(data.status == .completed)
        #expect(data.issuingParty.name == "Test Issuer")
        #expect(data.issuingParty.identifier == "https://issuer.example.com")
        #expect(data.dataFormat == .cbor)
        #expect(data.errorMessage == nil)
    }

    @Test("IssuanceLogData with failed status and error message")
    func testIssuanceLogDataFailed() {
        let log = TransactionLog(
            timestamp: 1700000000,
            status: .failed,
            errorMessage: "Proof invalid",
            type: .issuance,
            dataFormat: .json
        )
        let data = IssuanceLogData(log)
        #expect(data.status == .failed)
        #expect(data.errorMessage == "Proof invalid")
        #expect(data.issuingParty.name == "Unknown Issuer")
    }

    @Test("IssuanceLogData without issuingParty falls back to Unknown Issuer")
    func testIssuanceLogDataFallback() {
        let log = TransactionLog(
            timestamp: 1700000000,
            status: .completed,
            type: .issuance,
            dataFormat: .cbor
        )
        let data = IssuanceLogData(log)
        #expect(data.issuingParty.name == "Unknown Issuer")
        #expect(data.issuingParty.identifier == "")
    }

    // MARK: - TransactionLog with issuance type

    @Test("TransactionLog with issuance type and issuingParty")
    func testTransactionLogIssuance() {
        let issuingParty = TransactionLog.IssuingParty(name: "Issuer", identifier: "https://issuer.example.com", logoUrl: nil)
        let log = TransactionLog(
            timestamp: 1700000000,
            status: .completed,
            issuingParty: issuingParty,
            type: .issuance,
            dataFormat: .cbor
        )
        #expect(log.type == .issuance)
        #expect(log.issuingParty?.name == "Issuer")
        #expect(log.relyingParty == nil)
    }

    @Test("TransactionLog backward compatibility — issuingParty defaults to nil")
    func testTransactionLogIssuingPartyDefault() {
        let log = TransactionLog(
            timestamp: 1700000000,
            status: .completed,
            type: .presentation,
            dataFormat: .cbor
        )
        #expect(log.issuingParty == nil)
    }
}
