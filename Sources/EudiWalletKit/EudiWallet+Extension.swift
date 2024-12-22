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
    @discardableResult public func issuePAR(docType: String, scope: String? = "", identifier: String? = "", keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document {
        
        let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
        let (issuance, dataFormat) = try await openId4VCIService.issuePAR(docType: docType, scope: scope, identifier: identifier, promptMessage: promptMessage)
        
        return try await finalizeIssuing(data: issuance, docType: docType, format: dataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
    }
    
    public func getCredentials(docType: String, scope: String?, dpopNonce: String, code: String, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document {
        let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
        
        let credentialsOutcome = try await openId4VCIService.getCredentials(
            dpopNonce: dpopNonce,
            code: code,
            scope: scope
        )
        guard let issuanceOutcome = credentialsOutcome.0, let data = credentialsOutcome.1 else {
            throw  WalletError(description: "Error in getting access token")
        }
        
        return try await finalizeIssuing(data: issuanceOutcome, docType: docType, format: .cbor, issueReq: issueReq, openId4VCIService: openId4VCIService)
//        return try await finalizeIssuingCborDocument(id: id, data: cborData, docType: docType, format: .cbor, issueReq: issueReq, openId4VCIService: openId4VCIService)
        
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
    
//    func finalizeIssuing(id: String, data: IssuanceOutcome, docType: String?, format: DocDataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService) async throws -> WalletStorage.Document  {
//        var dataToSave: Data
//        var docTypeToSave: String?
//        var docMetadata: DocMetadata?
//        let pds = data.pendingOrDeferredStatus
//        switch data {
//        case .issued(let data, let str, let cc):
//            dataToSave = if format == .cbor, let data { data } else if let str, let data = str.data(using: .utf8) { data } else { Data() }
//            docMetadata = cc.convertToDocMetadata()
//            docTypeToSave = if format == .cbor, let data { IssuerSigned(data: [UInt8](data))?.issuerAuth.mso.docType ?? docType } else { docType }
//        case .deferred(let deferredIssuanceModel):
//            dataToSave = try JSONEncoder().encode(deferredIssuanceModel)
//            docMetadata = deferredIssuanceModel.configuration.convertToDocMetadata()
//            docTypeToSave = docType ?? "DEFERRED"
//        case .pending(let pendingAuthModel):
//            dataToSave = try JSONEncoder().encode(pendingAuthModel)
//            docMetadata = pendingAuthModel.configuration.convertToDocMetadata()
//            docTypeToSave = docType ?? "PENDING"
//        }
//        let newDocStatus: WalletStorage.DocumentStatus = data.isDeferred ? .deferred : (data.isPending ? .pending : .issued)
//        let newDocument = WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: dataToSave, secureAreaName: issueReq.secureAreaName, createdAt: Date(), metadata: docMetadata?.toData(), displayName: nil, status: newDocStatus)
//        if newDocStatus == .pending { await storage.appendDocModel(newDocument, uiCulture: uiCulture); return newDocument }
//        try await endIssueDocument(newDocument)
//        await storage.appendDocModel(newDocument, uiCulture: uiCulture)
//        await storage.refreshPublishedVars()
//        if pds == nil { try await storage.removePendingOrDeferredDoc(id: issueReq.id) }
//        return newDocument
//    }
    
    /*func finalizeIssuingCborDocument(id: String, data: Data, docType: String, format: DocDataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService) async throws -> WalletStorage.Document  {
        _ = IssuerSigned(data: [UInt8](data))
        guard let ddt = DocDataFormat(rawValue: format.rawValue) else { throw WalletError(description: "Invalid format \(format.rawValue)") }
        var issued: WalletStorage.Document
        
        issued = WalletStorage.Document(docType: docType, docDataFormat: format, data: data, secureAreaName: issueReq.secureAreaName, createdAt: Date(), metadata: data, displayName: nil, status: .issued)
        
//        issued = WalletStorage.Document(id: id,
//                                        docType: docTypeToSave,
//                                        docDataType: ddt,
//                                        data: dataToSave,
//                                        privateKeyType: .secureEnclaveP256,
//                                        privateKey: issueReq.keyData,
//                                        createdAt: Date(),
//                                        displayName: nil,
//                                        status: .issued)
        try await storageService.saveDocument(issued, allowOverwrite: true)
//        try issueReq.saveToStorage(storage.storageService, status: .issued)
//        try await endIssueDocument(issued)
//        await storage.appendDocModel(issued, uiCulture: uiCulture)
        await storage.refreshPublishedVars()
        return issued
    }*/
}
