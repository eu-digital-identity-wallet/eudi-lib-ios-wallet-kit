//
//  EudiWallet+WalletAppCompatibility.swift
//  EudiWalletKit
//

import Foundation
import MdocDataModel18013
import WalletStorage

extension EudiWallet {
	@MainActor
	@discardableResult public func issuePAR(issuerName: String, docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document? {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.issuePAR(docTypeIdentifier, credentialOptions: credentialOptions, keyOptions: keyOptions, promptMessage: promptMessage)
	}

	@MainActor
	@discardableResult public func resumePendingIssuanceDocuments(issuerName: String, pendingDoc: WalletStorage.Document, authorizationCode: String, nonce: String?, docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		return try await vciService.resumePendingIssuanceDocuments(
			pendingDoc: pendingDoc,
			authorizationCode: authorizationCode,
			nonce: nonce,
			docTypeIdentifiers: docTypeIdentifiers,
			credentialOptions: credentialOptions,
			keyOptions: keyOptions,
			promptMessage: promptMessage
		)
	}
}
