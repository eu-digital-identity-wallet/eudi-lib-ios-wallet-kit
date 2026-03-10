## Issue document using OpenID4VCI

The library provides the functionality to issue documents using OpenID4VCI. 

To issue a document
using this functionality, EudiWallet must be property initialized. 
If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document".
After issuing a document, the document data and corresponding private key are stored in the wallet storage.

### Issue document by docType or credential configuration identifier

When the document docType to be issued use the `issueDocument(issuerName:docTypeIdentifier:credentialOptions:keyOptions:)` method.

* Currently, only mso_mdoc and sd_jwt formats are supported

The following example shows how to issue an EUDI Personal ID document using OpenID4VCI:

```swift
do {
  let credentialOptions = CredentialOptions(credentialPolicy: .oneTimeUse, batchSize: 5)
  let keyOptions = KeyOptions(secureAreaName: "SecureEnclave")
  let doc = try await userWallet.issueDocument(
    issuerName: "eudi_pid_issuer", // Specify which issuer to use
    docTypeIdentifier: .msoMdoc(docType: EuPidModel.euPidDocType),
    credentialOptions: credentialOptions,
    keyOptions: keyOptions
  )
  // document has been added to wallet storage, you can display it
}
catch {
  // display error
}
```

You can also issue a document by passing a configuration identifier. The configuration identifiers can be retrieved from the issuer's metadata using the `getIssuerMetadata(issuerName:)` method.

```swift
// Get issuer metadata for a specific issuer
let metadata = try await wallet.getIssuerMetadata(issuerName: "eudi_pid_issuer")
// Use configuration identifier
let credentialOptions = CredentialOptions(credentialPolicy: .oneTimeUse, batchSize: 5)
let keyOptions = KeyOptions(secureAreaName: "SecureEnclave")
let doc = try await userWallet.issueDocuments(
  issuerName: "eudi_pid_issuer",
  docTypeIdentifiers: [.identifier("eu.europa.ec.eudi.pid_vc_sd_jwt")],
  credentialOptions: credentialOptions,
  keyOptions: keyOptions
)
```

For SD-JWT credentials, use the `.identifier` with vct:

```swift
let doc = try await userWallet.issueDocuments(
  issuerName: "eudi_pid_issuer",
  docTypeIdentifiers: [.identifier(vct: "eu.europa.ec.eudi.pid_vc_sd_jwt")],
  credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1),
  keyOptions: KeyOptions(secureAreaName: "SecureEnclave")
)
```

### Issue multiple documents

You can issue multiple documents in a single operation using the `issueDocuments(issuerName:docTypeIdentifiers:credentialOptions:keyOptions:)` method:

```swift
do {
  let credentialOptions = CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1)
  let keyOptions = KeyOptions(secureAreaName: "SecureEnclave")
  let documents = try await wallet.issueDocuments(
    issuerName: "eudi_pid_issuer",
    docTypeIdentifiers: [
       .identifier("eu.europa.ec.eudi.pid_mdoc"),
       .identifier("eu.europa.ec.eudi.pid_vc_sd_jwt")
    ],
    credentialOptions: credentialOptions,
    keyOptions: keyOptions
  )
  // all documents have been added to wallet storage
}
catch {
  // display error
}
```

This method efficiently issues multiple documents from the same issuer by creating a single credential offer with all requested document types.

#### Get Default Credential Options

You can retrieve issuer-recommended credential options before issuing:

```swift
let defaultOptions = try await wallet.getDefaultCredentialOptions(
  issuerName: "eudi_pid_issuer",
  docTypeIdentifier: .msoMdoc(docType: EuPidModel.euPidDocType)
)
```
### Resolving Credential offer

The library provides the `resolveOfferUrlDocTypes(uriOffer:)` method that resolves the credential offer URI.
The method returns the resolved `OfferedIssuanceModel` object that contains the offer's data (offered document types, issuer name and transaction code specification for pre-authorized flow). The offer's data can be displayed to the
user.

The following example shows how to resolve a credential offer:

```swift
 func resolveOfferUrlDocTypes(uriOffer: String, authFlowRedirectionURI: URL?) async throws -> OfferedIssuanceModel {
    return try await wallet.resolveOfferUrlDocTypes(uriOffer: uriOffer, authFlowRedirectionURI: authFlowRedirectionURI)
  }
```

After user acceptance of the offer, the selected documents can be issued using the `issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:configuration:)` method.
The `txCodeValue` parameter is not used in the case of the authorization code flow.

The following example shows how to issue documents by offer URL:

```swift
// Resolve the offer to get document models with recommended credential options
let offer = try await wallet.resolveOfferUrlDocTypes(uriOffer: offerUrl)

// Use the offered documents as-is with recommended settings, or customize them
let customizedDocTypes = offer.docModels.map { docModel in
  // You can customize credential options (batch size, credential policy)
  docModel.copy(
    credentialOptions: CredentialOptions(credentialPolicy: .oneTimeUse, batchSize: 2),
    keyOptions: KeyOptions(secureAreaName: "SecureEnclave")
  )
}

// Issue with customized settings
let newDocs = try await wallet.issueDocumentsByOfferUrl(
  offerUri: offerUrl,
  docTypes: customizedDocTypes,
  txCodeValue: txCode
)
```


### Authorization code flow

For the authorization code flow to work, the redirect URI must be specified specified by setting the the `openID4VciRedirectUri` property.
The user is redirected in an authorization web view to the issuer's authorization endpoint. After the user authenticates and authorizes the request, the issuer redirects the user back to the application with an authorization code. The library exchanges the authorization code for an access token and issues the document.

### Pre-Authorization code flow

When Issuer supports the pre-authorization code flow, the resolved offer will also contain the corresponding
information. Specifically, the `txCodeSpec` field in the ``OfferedIssuanceModel`` object will contain:

- The input mode, whether it is NUMERIC or TEXT
- The expected length of the input
- The description of the input

From the user's perspective, the application must provide a way to input the transaction code.

After user acceptance of the offer, the selected documents can be issued using the `issueDocumentsByOfferUrl(offerUri:docTypes:docTypeKeyOptions:txCodeValue:)` method.
When the transaction code is provided, the issuance process can be resumed by calling the above-mentioned method and passing the transaction code in the `txCodeValue` parameter.

### Dynamic issuance

Wallet kit supports the Dynamic [PID based issuance](https://github.com/eu-digital-identity-wallet/eudi-wallet-product-roadmap/issues/82)

After calling `issueDocument(issuerName:docTypeIdentifier:credentialOptions:keyOptions:)`, `issueDocuments(issuerName:docTypeIdentifiers:credentialOptions:keyOptions:)`, or `issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:configuration:)` the wallet application need to check if the doc is pending and has an `authorizePresentationUrl` property. If the property is present, the application should perform the OpenID4VP presentation using the presentation URL. On success, the `resumePendingIssuance(issuerName:pendingDoc:webUrl:credentialOptions:keyOptions:)` method should be called with the authorization URL provided by the server.

```swift
if let urlString = newDocs.last?.authorizePresentationUrl { 
	// perform openid4vp presentation using the urlString 
	// on success call resumePendingIssuance using the authorization url
	let resumedDoc = try await wallet.resumePendingIssuance(
		issuerName: "eudi_pid_issuer",
		pendingDoc: pendingDocument,
		webUrl: authorizationURL,
		credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1),
		keyOptions: KeyOptions(secureAreaName: "SecureEnclave")
	)
}
```

#### Deferred Issuance

For deferred document issuance, use the `requestDeferredIssuance(issuerName:deferredDoc:credentialOptions:keyOptions:)` method:

```swift
let issuedDoc = try await wallet.requestDeferredIssuance(
	issuerName: "eudi_pid_issuer",
	deferredDoc: deferredDocument,
	credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1),
	keyOptions: KeyOptions(secureAreaName: "SecureEnclave")
)
```