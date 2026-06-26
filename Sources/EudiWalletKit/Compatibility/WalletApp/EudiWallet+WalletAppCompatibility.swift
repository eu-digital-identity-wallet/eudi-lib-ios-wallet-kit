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

	public func storedAuthorizedRequestParams(docId: WalletStorage.Document.ID) async throws -> AuthorizedRequestParams? {
		let status: DocumentStatus =  if storage.docModels.contains(where: { $0.id == docId }) { .issued } else if storage.deferredDocuments.contains(where: { $0.id == docId }) { .deferred } else if storage.pendingDocuments.contains(where: { $0.id == docId }) { .pending } else { .issued }

		guard let docMetadata = try await storage.storageService.loadDocumentMetadata(id: docId, status: status) else {
			throw WalletError(description: "Issued document metadata not found for id: \(docId)")
		}
		guard let data = docMetadata.authorizedRequestData,
			  let authorizedData = try? JSONDecoder().decode(AuthorizedRequestData.self, from: data) else {
			return nil
		}
		return AuthorizedRequestParams(from: authorizedData.toAuthorizedRequest())
	}

	@MainActor
	@discardableResult public func getCredentialsWithRefreshToken(issuerName: String, docTypeIdentifiers: [DocTypeIdentifier], authorizedRequestParams: AuthorizedRequestParams, issuerDPopConstructorParam: IssuerDPoPConstructorParam, docIds: [String], credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, forceRefreshToken: Bool = false) async throws -> (documents: [WalletStorage.Document], authorizedRequestParams: AuthorizedRequestParams) {
		guard let vciService = OpenId4VCIServiceRegistry.shared.get(name: issuerName) else {
			throw WalletError(description: "No OpenId4VCI service registered for name \(issuerName)")
		}
		let authorized = try authorizedRequestParams.toAuthorizedRequest()
		let (documents, refreshed) = try await vciService.getCredentialsWithRefreshToken(
			docTypeIdentifiers: docTypeIdentifiers,
			authorized: authorized,
			issuerDPopConstructorParam: issuerDPopConstructorParam,
			docIds: docIds,
			credentialOptions: credentialOptions,
			keyOptions: keyOptions,
			promptMessage: promptMessage,
			forceRefreshToken: forceRefreshToken
		)
		return (documents, AuthorizedRequestParams(from: refreshed))
	}
}
