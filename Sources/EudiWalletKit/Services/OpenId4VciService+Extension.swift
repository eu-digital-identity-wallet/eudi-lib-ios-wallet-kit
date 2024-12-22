//
//  Untitled.swift
//  EudiWalletKit
//
//  Created by Pankaj Sachdeva on 20.12.24.
//

import Foundation
@preconcurrency import OpenID4VCI
import MdocDataModel18013

extension OpenId4VCIService {
    
    func issuePAR(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
        guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope must be provided") }
        logger.log(level: .info, "Issuing document with docType or scope or identifier: \(docTypeOrScopeOrIdentifier)")
        let res = try await issueByDocType(docType, scope: scope, identifier: identifier, promptMessage: promptMessage)
        return res
    }
    
    func getCredentials(dpopNonce: String, code: String, scope: String?, claimSet: ClaimSet? = nil) async throws -> (IssuanceOutcome?, Data?) {
        do {
            return (nil, nil)
        } catch  {
            throw WalletError(description: "Invalid issuer metadata")
        }
        return (nil, nil)
    }
}
