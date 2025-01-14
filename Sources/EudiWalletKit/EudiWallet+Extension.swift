//
//  EudiWallet+Extension.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 19.12.24.
//

import Foundation
import MdocDataModel18013
import WalletStorage
import LocalAuthentication
import OpenID4VCI

extension EudiWallet {
    @discardableResult public func issuePAR(docType: String, scope: String? = "", identifier: String? = "", keyOptions: KeyOptions? = nil, promptMessage: String? = nil, wia: WalletInstanceAttestationPAR) async throws -> WalletStorage.Document {
        
        let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
        let (issuance, dataFormat) = try await openId4VCIService.issuePAR(docType: docType, scope: scope, identifier: id, promptMessage: promptMessage, wia: wia)
        
        return try await finalizeIssuing(data: issuance, docType: docType, format: dataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
    }
    
    public func getCredentials(docType: String, scope: String?, dpopNonce: String, code: String, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document {
        let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
        let credentialsOutcome = try await openId4VCIService.getCredentials(
            dpopNonce: dpopNonce,
            code: code,
            scope: scope,
            identifier: id,
            docType: docType
        )
        guard let issuanceOutcome = credentialsOutcome.0, let _ = credentialsOutcome.1 else {
            throw  WalletError(description: "Error in getting access token")
        }
        
        return try await finalizeIssuing(data: issuanceOutcome, docType: docType, format: .cbor, issueReq: issueReq, openId4VCIService: openId4VCIService)
        
    }
    
    private func prepareIssuingService(id: String, docType: String?, displayName: String?, keyOptions: KeyOptions?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
        guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
        guard openID4VciConfig?.clientId != nil else { throw WalletError(description: "clientId not defined")}
        guard openID4VciConfig?.authFlowRedirectionURI != nil else { throw WalletError(description: "Auth flow Redirect URI not defined")}
        let id: String = UUID().uuidString
        let issueReq = try await Self.authorizedAction(action: {
            return try await beginIssueDocument(id: id, keyOptions: keyOptions)
        }, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(displayName ?? docType ?? "", comment: "")))
        guard let issueReq else { throw LAError(.userCancel)}
        let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, uiCulture: uiCulture, config: openID4VciConfig ?? OpenId4VCIConfig(clientId: Self.defaultClientId, authFlowRedirectionURI: Self.defaultOpenID4VciRedirectUri), urlSession: urlSession)
        return (issueReq, openId4VCIService, id)
    }
    
}
