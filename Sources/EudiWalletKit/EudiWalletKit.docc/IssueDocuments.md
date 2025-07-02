#  Issue documents

The library provides the functionality to issue documents using OpenID4VCI. 

### Overview

To issue a document
using this functionality, EudiWallet must be property initialized. 
If ``EudiWallet/userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document".
After issuing a document, the document data and corresponding private key are stored in the wallet storage.

### Issue document by docType
When the document docType to be issued use the ``EudiWallet/issueDocument(docTypeIdentifier:keyOptions:promptMessage:)`` method.

__Important Notes__:

- For the 'SecureEnclave' secure area, only ES256 algorithm is supported for signing OpenId4CVI proof of possession of the
public/private key pair.

The following example shows how to issue an EUDI Personal ID document using OpenID4VCI:

```swift
do {
	let keyOptions = try await wallet.getDefaultKeyOptions(.msoMdoc("org.iso.18013.5.1.mDL"))
	let doc = try await userWallet.issueDocument(.msoMdoc("org.iso.18013.5.1.mDL"), keyOptions: keyOptions
}
catch {
  // display error
}
```

You can also issue a document by passing a `configurationIdentifier` case. The configuration identifiers can be retrieved from the issuer's metadata,  using the `getIssuerMetadata` method.

```swift
  // get current issuer metadata
  let configuration = try await wallet.getIssuerMetadata()
  ...
  let doc = try await userWallet.issueDocument(.configurationIdentifier("eu.europa.ec.eudi.pid_vc_sd_jwt"))
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

After user acceptance of the offer, the selected documents can be issued using the `issueDocumentsByOfferUrl(offerUri:docTypes:docTypeKeyOptions:txCodeValue:)` method.
The `txCodeValue` parameter is not used in the case of the authorization code flow.
The following example shows how to issue documents by offer URL:
  ```swift
 // When resolving an offer, key options are now included
 let offer = try await wallet.resolveOfferUrlDocTypes(uriOffer: offerUrl)
 for docModel in offer.docModels {
	// use recommended key options or modify them
	 let docTypes = offer.docModels.map { $0.copy(keyOptions: KeyOptions(credentialPolicy: .oneTimeUse, batchSize: 2))
     // Issue with optimal settings
     let newDocs = try await wallet.issueDocumentsByOfferUrl(offerUri: offerUrl, docTypes: docTypes, txCodeValue: txCode)
 }
 ```

### Authorization code flow

For the authorization code flow to work, the redirect URI must be specified specified by setting the the ``EudiWallet/openID4VciConfig`` property.
The user is redirected in an authorization web view to the issuer's authorization endpoint. After the user authenticates and authorizes the request, the issuer redirects the user back to the application with an authorization code. The library exchanges the authorization code for an access token and issues the document.

### Pre-Authorization code flow

When Issuer supports the pre-authorization code flow, the resolved offer will also contain the corresponding
information. Specifically, the `txCodeSpec` field in the ``OfferedIssuanceModel`` object will contain:

- The input mode, whether it is NUMERIC or TEXT
- The expected length of the input
- The description of the input

From the user's perspective, the application must provide a way to input the transaction code.

After user acceptance of the offer, the selected documents can be issued using the ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:promptMessage:useSecureEnclave:claimSet:)`` method.
When the transaction code is provided, the issuance process can be resumed by calling the above-mentioned method and passing the transaction code in the `txCodeValue` parameter.

### Dynamic issuance
Wallet kit supports the Dynamic [PID based issuance](https://github.com/eu-digital-identity-wallet/eudi-wallet-product-roadmap/issues/82)

After calling ``EudiWallet/issueDocument(docType:scope:identifier:keyOptions:promptMessage:)`` or ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:docTypeKeyOptions:txCodeValue:promptMessage:claimSet:)`` the wallet application need to check if the doc is pending and has a `authorizePresentationUrl` property. If the property is present, the application should perform the OpenID4VP presentation using the presentation URL. On success, the ``EudiWallet/resumePendingIssuance(pendingDoc:webUrl:)`` method should be called with the authorization URL provided by the server.
```swift
if let urlString = newDocs.last?.authorizePresentationUrl { 
	// perform openid4vp presentation using the urlString 
	// on success call resumePendingIssuance using the authorization url  
```
