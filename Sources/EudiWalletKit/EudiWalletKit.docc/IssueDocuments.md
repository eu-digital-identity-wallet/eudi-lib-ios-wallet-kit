## Issue document using OpenID4VCI

The library provides the functionality to issue documents using OpenID4VCI. 

To issue a document
using this functionality, EudiWallet must be property initialized. 
If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document".
After issuing a document, the document data and corresponding private key are stored in the wallet storage.

### Issue document by docType

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
let doc = try await userWallet.issueDocument(
  issuerName: "eudi_pid_issuer",
  docTypeIdentifier: .identifier("eu.europa.ec.eudi.pid_vc_sd_jwt"),
  credentialOptions: credentialOptions,
  keyOptions: keyOptions
)
```

For SD-JWT credentials, use the `.sdJwt` identifier:

```swift
let doc = try await userWallet.issueDocument(
  issuerName: "eudi_pid_issuer",
  docTypeIdentifier: .sdJwt(vct: "eu.europa.ec.eudi.pid_vc_sd_jwt"),
  credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1),
  keyOptions: KeyOptions(secureAreaName: "SecureEnclave")
)
```

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
 func resolveOfferUrlDocTypes(uriOffer: String) async throws -> OfferedIssuanceModel {
    return try await wallet.resolveOfferUrlDocTypes(uriOffer: uriOffer)
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