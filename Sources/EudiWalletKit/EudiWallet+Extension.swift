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
import SwiftyJSON

extension EudiWallet {
    @MainActor
    @discardableResult public func issuePAR(docType: String?, scope: String? = "", identifier: String? = "", keyOptions: KeyOptions? = nil, promptMessage: String? = nil, wia: IssuerDPoPConstructorParam) async throws -> WalletStorage.Document {
        
        let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
        let (issuance, dataFormat) = try await openId4VCIService.issuePAR(docType: docType, scope: scope, identifier: id, promptMessage: promptMessage, wia: wia)
        
        return try await finalizeIssuing(issueOutcome: issuance, docType: docType, format: dataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
    }
    
	@MainActor
	public func getCredentials(docType: String, scope: String?, dpopNonce: String, code: String, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, docDataFormat: DocDataFormat, issuerDPopConstructorParam: IssuerDPoPConstructorParam) async throws -> (WalletStorage.Document?, AuthorizedRequestParams?) {
        let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
        let credentialsOutcome = try await openId4VCIService.getCredentials(
            dpopNonce: dpopNonce,
            code: code,
            scope: scope,
            identifier: id,
			docType: docType,
			issuerDPopConstructorParam: issuerDPopConstructorParam
        )
		guard let issuanceOutcome = credentialsOutcome.0,
				let _ = credentialsOutcome.1,
				let authorizedRequestParams = credentialsOutcome.2 else {
            throw  WalletError(description: "Error in getting access token")
        }
		
		var document: WalletStorage.Document?
		switch issuanceOutcome {
		case .issued(let jsonData, let str, let cc):
			
			if let str = str {
				document = try await finalizeIssuing(issueOutcome: .issued(nil, str, cc), docType: docType, format: docDataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
			} else {
				guard let jsonData else {throw WalletError.generic("unable to finalizeIssuing") }
				
				let jsonObject = try? JSON(data: jsonData)
				
				if let jsonArray = jsonObject?.arrayObject as? [String] {
					for item in jsonArray {
						document = try await finalizeIssuing(issueOutcome: .issued(item.data(using: .utf8), item, cc), docType: docType, format: docDataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
					}
					} else {
						print("Failed to parse JSON as an array of strings")
					}
			}
			
		default:
			print(#function, "Unhandled issuance outcome")
		}
		if let metadata = document?.metadata {
			print(String(data: metadata, encoding: .utf8))
		}
		return (document, authorizedRequestParams)
    }
	
	@MainActor
	public func getCredentials(with refreshToken: String, accessToken: String, docType: String, scope: String?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, docDataFormat: DocDataFormat, issuerDPopConstructorParam: IssuerDPoPConstructorParam) async -> (WalletStorage.Document?, AuthorizedRequestParams?) {
		do {
			let (issueReq, openId4VCIService, id) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
			let authRequest: AuthorizedRequest = .noProofRequired(accessToken: try IssuanceAccessToken(accessToken: accessToken, tokenType: .none), refreshToken: try IssuanceRefreshToken(refreshToken: refreshToken), credentialIdentifiers: nil, timeStamp: 3600, dPopNonce: nil)
			let credentialsOutcome = try await openId4VCIService.getCredentialsWithRefreshToken(docType, scope: scope, claimSet: nil, identifier: nil, authorizedRequest: authRequest, issuerDPopConstructorParam: issuerDPopConstructorParam)
			
			guard let issuanceOutcome = credentialsOutcome.0,
					let _ = credentialsOutcome.1,
					let authorizedRequestParams = credentialsOutcome.2 else {
				throw  WalletError(description: "Error in getting access token")
			}
			
			var document: WalletStorage.Document?
			switch issuanceOutcome {
			case .issued(let jsonData, let str, let cc):
				
				if let str = str {
					document = try await finalizeIssuing(issueOutcome: .issued(nil, str, cc), docType: docType, format: docDataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
				} else {
					guard let jsonData else {throw WalletError.generic("unable to finalizeIssuing") }
					
					let jsonObject = try? JSON(data: jsonData)
					
					if let jsonArray = jsonObject?.arrayObject as? [String] {
						for item in jsonArray {
							document = try await finalizeIssuing(issueOutcome: .issued(item.data(using: .utf8), item, cc), docType: docType, format: docDataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
						}
						} else {
							print("Failed to parse JSON as an array of strings")
						}
				}
				
			default:
				print(#function, "Unhandled issuance outcome")
			}
			if let metadata = document?.metadata {
				print(String(data: metadata, encoding: .utf8))
			}
			return (document, authorizedRequestParams)
		} catch {
			return (nil, nil)
		}
	}
    
    private func prepareIssuingService(id: String, docType: String?, displayName: String?, keyOptions: KeyOptions?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
        guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
        guard openID4VciConfig?.client != nil else { throw WalletError(description: "clientId not defined")}
        guard openID4VciConfig?.authFlowRedirectionURI != nil else { throw WalletError(description: "Auth flow Redirect URI not defined")}
        let id: String = UUID().uuidString
        let issueReq = try await Self.authorizedAction(action: {
            return try await beginIssueDocument(id: id, keyOptions: keyOptions)
        }, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(displayName ?? docType ?? "", comment: "")))
        guard let issueReq else { throw LAError(.userCancel)}
        let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, uiCulture: uiCulture, config: openID4VciConfig ?? OpenId4VCIConfig(client: Self.defaultClient, authFlowRedirectionURI: Self.defaultOpenID4VciRedirectUri), urlSession: urlSession)
        return (issueReq, openId4VCIService, id)
    }
    
}
