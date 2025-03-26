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
        
		let (issueReq, openId4VCIService, _) = try await prepareIssuingService(id: UUID().uuidString, docType: docType, displayName: nil, keyOptions: keyOptions, promptMessage: promptMessage)
        
		let (issuance, dataFormat) = try await openId4VCIService.issuePAR(docType: docType, scope: scope, identifier: identifier, promptMessage: promptMessage, wia: wia)
        
        return try await finalizeIssuing(issueOutcome: issuance, docType: docType, format: dataFormat, issueReq: issueReq, openId4VCIService: openId4VCIService)
    }
	
	@MainActor
	@discardableResult public func resumePendingIssuanceDocuments(pendingDoc: WalletStorage.Document, keyOptions: KeyOptions? = nil, authorizationCode: String, issuerDPopConstructorParam: IssuerDPoPConstructorParam) async throws -> [WalletStorage.Document] {
		guard pendingDoc.status == .pending else { throw WalletError(description: "Invalid document status") }
		let openId4VCIService = try await prepareIssuing(id: pendingDoc.id, docType: pendingDoc.docType, displayName: nil, keyOptions: keyOptions, disablePrompt: true, promptMessage: nil)
		let outcome = try await openId4VCIService.resumePendingIssuance(pendingDoc: pendingDoc, authorizationCode: authorizationCode, issuerDPopConstructorParam: issuerDPopConstructorParam)
		if case .pending(_) = outcome { return [pendingDoc] }
		
		var documents = [WalletStorage.Document]()
		
		switch outcome {
		case .issued(let data, let string, let credential):
			if let string = string {//cbor
				let credentialString = string.components(separatedBy: ",")
				for cred in credentialString {
					let issuenceOutcome: IssuanceOutcome = .issued(Data(base64URLEncoded: cred), cred, credential)
					
					let doc = try await finalizeIssuing(issueOutcome: issuenceOutcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: openId4VCIService.issueReq, openId4VCIService: openId4VCIService)
					documents.append(doc)
				}
			}
			
			if let data = data, let json = try? JSON(data: data), let stringArray = json.arrayObject as? [String] {//sdjwt
				for cred in stringArray {
					let issuenceOutcome: IssuanceOutcome = .issued(nil, cred, credential)
					
					let doc = try await finalizeIssuing(issueOutcome: issuenceOutcome, docType: pendingDoc.docType, format: pendingDoc.docDataFormat, issueReq: openId4VCIService.issueReq, openId4VCIService: openId4VCIService)
					documents.append(doc)
				}
			}
		default:
			break
		}
		return documents
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
			return (document, authorizedRequestParams)
		} catch {
			return (nil, nil)
		}
	}
    
    private func prepareIssuingService(id: String, docType: String?, displayName: String?, keyOptions: KeyOptions?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
        guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
        
        let id: String = UUID().uuidString
        let issueReq = try await Self.authorizedAction(action: {
            return try await beginIssueDocument(id: id, keyOptions: keyOptions)
        }, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(displayName ?? docType ?? "", comment: "")))
        guard let issueReq else { throw LAError(.userCancel)}
        let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, uiCulture: uiCulture, config: openID4VciConfig .toOpenId4VCIConfig(), urlSession: urlSession)
        return (issueReq, openId4VCIService, id)
    }
    
}
