//
//  OpenId4VciService+WalletAppCompatibility.swift
//  EudiWalletKit
//

import Foundation
import OpenID4VCI
import MdocDataModel18013
import JOSESwift
import Security
import WalletStorage
import class eudi_lib_sdjwt_swift.CompactParser

extension OpenId4VciService {
	func issuePAR(_ docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document? {
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(
			id: UUID().uuidString,
			docTypeIdentifier: docTypeIdentifier,
			displayName: nil,
			credentialOptions: usedCredentialOptions,
			keyOptions: keyOptions,
			disablePrompt: false,
			promptMessage: promptMessage
		)

		let (credentialIssuerIdentifier, metadata) = try await getIssuerMetadata()
		guard let authorizationServer = metadata.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}

		let authServerMetadata = await AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking),
			oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)
		).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()

		let configuration = try getCredentialConfiguration(
			credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString,
			issuerDisplay: metadata.display,
			credentialsSupported: metadata.credentialsSupported,
			identifier: docTypeIdentifier.configurationIdentifier,
			docType: docTypeIdentifier.docType,
			vct: docTypeIdentifier.vct,
			batchCredentialIssuance: metadata.batchCredentialIssuance,
			dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name),
			clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)
		)

		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metadata,
			credentialConfigurationIdentifiers: [configuration.configurationIdentifier],
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)

		let issuer = try await getIssuerForWalletAppCompatibility(offer: offer)
		let parPlaced = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
		authRequested = parPlaced

		let metadataKey = UUID().uuidString
		Self.credentialOfferCache[metadataKey] = offer

		let outcome = IssuanceOutcome.pending(
			PendingIssuanceModel(
				pendingReason: .presentation_request_url(parPlaced.authorizationCodeURL.url.absoluteString),
				configuration: configuration,
				metadataKey: metadataKey,
				pckeCodeVerifier: parPlaced.pkceVerifier.codeVerifier,
				pckeCodeVerifierMethod: parPlaced.pkceVerifier.codeVerifierMethod,
				state: parPlaced.state
			)
		)

		return try await finalizeIssuing(
			issueOutcome: outcome,
			docType: docTypeIdentifier.docType,
			format: configuration.format,
			issueReq: issueReq,
			deleteId: nil
		)
	}

	func resumePendingIssuanceDocuments(pendingDoc: WalletStorage.Document, authorizationCode: String, nonce: String?, docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		guard pendingDoc.status == .pending else {
			throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")
		}

		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url = model.pendingReason else {
			throw WalletError(description: "Unknown pending reason: \(model.pendingReason)")
		}
		if Self.credentialOfferCache[model.metadataKey] == nil, let cachedOffer = Self.credentialOfferCache.values.first {
			Self.credentialOfferCache[model.metadataKey] = cachedOffer
		}
		guard let offer = Self.credentialOfferCache[model.metadataKey] else {
			throw WalletError(description: "Pending issuance cannot be completed")
		}

		let (credentialIssuerIdentifier, metadata) = try await getIssuerMetadata()
		guard let authorizationServer = metadata.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}

		let authServerMetadata = await AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking),
			oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)
		).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()

		let credentialConfigurations = try docTypeIdentifiers.map {
			try getCredentialConfiguration(
				credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString,
				issuerDisplay: metadata.display,
				credentialsSupported: metadata.credentialsSupported,
				identifier: $0.configurationIdentifier,
				docType: $0.docType,
				vct: $0.vct,
				batchCredentialIssuance: metadata.batchCredentialIssuance,
				dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name),
				clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)
			)
		}

		let uiCulture = self.uiCulture
		let config = self.config
		let networking = self.networking
		let storage = self.storage
		let storageService = self.storageService

		let docTypes = credentialConfigurations.map {
			OfferedDocModel(
				credentialConfigurationIdentifier: $0.configurationIdentifier.value,
				docType: $0.docType,
				vct: $0.vct,
				scope: $0.scope ?? "",
				identifier: $0.configurationIdentifier.value,
				displayName: $0.display.getName(uiCulture) ?? $0.docType ?? $0.vct ?? $0.scope ?? "",
				algValuesSupported: $0.credentialSigningAlgValuesSupported,
				claims: $0.claims,
				credentialOptions: credentialOptions,
				keyOptions: keyOptions
			)
		}

		let issuer = try await getIssuerForWalletAppCompatibility(offer: offer, nonce: nonce)
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorizationCodeURL = try AuthorizationCodeURL(urlString: pendingDoc.authorizePresentationUrl ?? "")
		let request = AuthorizationRequested(
			credentials: [try .init(value: model.configuration.configurationIdentifier.value)],
			authorizationCodeURL: authorizationCodeURL,
			pkceVerifier: pkceVerifier,
			state: model.state,
			configurationIds: [model.configuration.configurationIdentifier],
			dpopNonce: nil
		)
		let authorized = try await issuer.authorizeWithAuthorizationCode(
			serverState: request.state,
			request: request,
			authorizationCode: try AuthorizationCode(value: authorizationCode),
			authorizationDetailsInTokenRequest: .doNotInclude,
			grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))
		)
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString
		let issuerIdentifier = offer.credentialIssuerIdentifier.url.absoluteString
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString

		return try await withThrowingTaskGroup(of: WalletStorage.Document.self) { group in
			for (index, docType) in docTypes.enumerated() {
				group.addTask {
					let service = try OpenId4VciService(
						uiCulture: uiCulture,
						config: config,
						networking: networking,
						storage: storage,
						storageService: storageService
					)
					let usedCredentialOptions = try await service.validateCredentialOptions(
						docTypeIdentifier: docType.docTypeIdentifier!,
						credentialOptions: docType.credentialOptions,
						offer: offer
					)
					try await service.prepareIssuing(
						id: UUID().uuidString,
						docTypeIdentifier: docType.docTypeIdentifier!,
						displayName: index > 0 ? nil : docTypes.map(\.displayName).joined(separator: ", "),
						credentialOptions: usedCredentialOptions,
						keyOptions: docType.keyOptions,
						disablePrompt: index > 0,
						promptMessage: promptMessage
					)
					await service.setAdditionalOptions(docType.identifier ?? "")
					let (bindingKeys, publicKeys) = try await service.initSecurityKeys(credentialConfigurations[index])
					let outcome = try await service.issueDocumentByOfferUrl(
						issuer: issuer,
						offer: offer,
						authorizedOutcome: .authorized(authorized),
						configuration: credentialConfigurations[index],
						bindingKeys: bindingKeys,
						publicKeys: publicKeys,
						promptMessage: promptMessage
					)

					return try await self.finalizeIssuing(
						issueOutcome: outcome,
						docType: docType.docTypeOrVct,
						format: credentialConfigurations[index].format,
						issueReq: service.issueReq,
						deleteId: nil,
						dpopKeyId: nil,
						issuerName: issuerName,
						issuerIdentifier: issuerIdentifier,
						issuerLogoUrl: issuerLogoUrl
					)
				}
			}

			var documents = [WalletStorage.Document]()
			for try await document in group {
				documents.append(document)
			}
			return documents
		}
	}

	private func setAdditionalOptions(_ value: String) {
		issueReq.keyOptions?.additionalOptions = Data(value.utf8)
	}

	func getCredentialsWithRefreshToken(docTypeIdentifier: DocTypeIdentifier, authorizedRequest: AuthorizedRequest, issuerDPopConstructorParam: IssuerDPoPConstructorParam, docId: String) async throws -> (IssuanceOutcome?, DocDataFormat?, AuthorizedRequest?) {
		let dpopConstructor = DPoPConstructor(
			algorithm: JWSAlgorithm(.ES256),
			jwk: issuerDPopConstructorParam.jwk,
			privateKey: .secKey(issuerDPopConstructorParam.privateKey)
		)

		let (credentialIssuerIdentifier, metadata) = try await getIssuerMetadata()
		let (issuer, offer) = try await fetchIssuerAndOfferWithLatestMetadata(
			docTypeIdentifier: docTypeIdentifier,
			dpopConstructor: dpopConstructor
		)

		let refreshed = try await issuer.refresh(clientId: config.clientId, authorizedRequest: authorizedRequest)
		guard let authorizationServer = metadata.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid issuer metadata")
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking),
			oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)
		).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		let configuration = try getCredentialConfiguration(
			credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString,
			issuerDisplay: metadata.display,
			credentialsSupported: metadata.credentialsSupported,
			identifier: docTypeIdentifier.configurationIdentifier,
			docType: docTypeIdentifier.docType,
			vct: docTypeIdentifier.vct,
			batchCredentialIssuance: metadata.batchCredentialIssuance,
			dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map { $0.name },
			clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map { $0.name }
		)

		let (bindingKeys, publicKeys) = try await initSecurityKeys(configuration)
		let issuanceOutcome = try await compatibilitySubmissionUseCase(
			refreshed,
			issuer: issuer,
			configuration: configuration,
			bindingKeys: bindingKeys,
			publicKeys: publicKeys
		)
		_ = offer
		return (issuanceOutcome, configuration.format, refreshed)
	}

	private func fetchIssuerAndOfferWithLatestMetadata(docTypeIdentifier: DocTypeIdentifier, dpopConstructor: DPoPConstructorType) async throws -> (Issuer, CredentialOffer) {
		let (credentialIssuerIdentifier, metadata) = try await getIssuerMetadata()
		guard let authorizationServer = metadata.authorizationServers?.first else {
			throw WalletError(description: "Invalid issuer metadata")
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher(session: networking),
			oauthFetcher: Fetcher(session: networking)
		).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		let configuration = try getCredentialConfiguration(
			credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString,
			issuerDisplay: metadata.display,
			credentialsSupported: metadata.credentialsSupported,
			identifier: docTypeIdentifier.configurationIdentifier,
			docType: docTypeIdentifier.docType,
			vct: docTypeIdentifier.vct,
			batchCredentialIssuance: metadata.batchCredentialIssuance,
			dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map { $0.name },
			clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map { $0.name }
		)
		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metadata,
			credentialConfigurationIdentifiers: [configuration.configurationIdentifier],
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)
		let vciConfig = try await config.toOpenId4VCIConfig(
			credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString,
			clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported
		)
		let issuer = try Issuer(
			authorizationServerMetadata: offer.authorizationServerMetadata,
			issuerMetadata: offer.credentialIssuerMetadata,
			config: vciConfig,
			parPoster: Poster(session: networking),
			tokenPoster: Poster(session: networking),
			requesterPoster: Poster(session: networking),
			deferredRequesterPoster: Poster(session: networking),
			notificationPoster: Poster(session: networking),
			noncePoster: Poster(session: networking),
			dpopConstructor: dpopConstructor
		)
		return (issuer, offer)
	}

	private func getIssuerForWalletAppCompatibility(offer: CredentialOffer, nonce: String? = nil) async throws -> Issuer {
		var dpopConstructor: DPoPConstructorType? = nil
		if config.requireDpop {
			dpopConstructor = try await config.makePoPConstructor(
				popUsage: .dpop,
				privateKeyId: issueReq.dpopKeyId,
				algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported,
				keyOptions: config.dpopKeyOptions
			)
		}
		let vciConfig = try await config.toOpenId4VCIConfigWithPrivateKey(
			credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString,
			clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported
		)
		_ = nonce
		return try Issuer(
			authorizationServerMetadata: offer.authorizationServerMetadata,
			issuerMetadata: offer.credentialIssuerMetadata,
			config: vciConfig,
			parPoster: Poster(session: networking),
			tokenPoster: Poster(session: networking),
			requesterPoster: Poster(session: networking),
			deferredRequesterPoster: Poster(session: networking),
			notificationPoster: Poster(session: networking),
			noncePoster: Poster(session: networking),
			dpopConstructor: dpopConstructor
		)
	}

	private func compatibilitySubmissionUseCase(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data]) async throws -> IssuanceOutcome {
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier)
		let requestOutcome = try await issuer.requestCredential(
			request: authorized,
			bindingKeys: bindingKeys,
			requestPayload: payload
		) {
			Issuer.createResponseEncryptionSpec($0)
		}

		switch requestOutcome {
		case .success(let response):
			guard let result = response.credentialResponses.first else {
				throw PresentationSession.makeError(str: "No credential response results available")
			}

			switch result {
			case .deferred(let transactionId, let interval):
				logger.info("Credential issuance deferred with transactionId: \(transactionId), interval: \(interval) seconds")
				let derKeyData: Data? = if let encryptionSpec = await issuer.deferredResponseEncryptionSpec, let key = encryptionSpec.privateKey {
					try secCall { SecKeyCopyExternalRepresentation(key, $0) } as Data
				} else {
					nil
				}
				let deferredModel = await DeferredIssuanceModel(
					deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!,
					transactionId: transactionId,
					publicKeys: publicKeys,
					derKeyData: derKeyData,
					timeStamp: authorized.timeStamp
				)
				return .deferred(deferredModel, configuration, authorized)
			case .issued(let format, _, _, _):
				let credentials = response.credentialResponses.compactMap {
					if case let .issued(_, credential, _, _) = $0 { credential } else { nil }
				}
				return try await compatibilityHandleCredentialResponse(
					credentials: credentials,
					publicKeys: publicKeys,
					format: format,
					configuration: configuration,
					authorized: authorized
				)
			}
		case .invalidProof(let errorDescription):
			throw PresentationSession.makeError(str: "Issuer error: " + (errorDescription ?? "The proof is invalid"))
		case .failed(let error):
			throw PresentationSession.makeError(str: error.localizedDescription)
		}
	}

	private func compatibilityHandleCredentialResponse(credentials: [Credential], publicKeys: [Data], format: String?, configuration: CredentialConfiguration, authorized: AuthorizedRequest) async throws -> IssuanceOutcome {
		logger.info("Credential issued with format \(format ?? "unknown")")
		let toData: (String) -> Data = { str in
			if configuration.format == .cbor {
				return Data(base64URLEncoded: str) ?? Data()
			}
			return str.data(using: .utf8) ?? Data()
		}

		let credData: [(Data, Data)] = try credentials.enumerated().flatMap { index, credential -> [(Data, Data)] in
			if case let .string(str) = credential {
				logger.notice("Issued credential data:\n\(str)")
				return [(toData(str), publicKeys[index])]
			}
			if case let .json(json) = credential, json.type == .array, json.first != nil {
				let compactParser = CompactParser()
				let response = json.map { entry in
					let str = (try? compactParser.stringFromJwsJsonObject(entry.1["credential"])) ?? entry.1["credential"].stringValue
					return (toData(str), publicKeys[index])
				}
				logger.notice("Issued credential data:\n\(String(data: response.first?.0 ?? Data(), encoding: .utf8) ?? "")")
				return response
			}
			throw PresentationSession.makeError(str: "Invalid credential")
		}

		return .issued(credData, configuration, authorized)
	}
}
