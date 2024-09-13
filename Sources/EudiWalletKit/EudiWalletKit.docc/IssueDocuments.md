#  Issue documents

The library provides the functionality to issue documents using OpenID4VCI. 

### Overview

To issue a document
using this functionality, EudiWallet must be property initialized. 
If ``EudiWallet/userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document".
After issuing a document, the document data and corresponding private key are stored in the wallet storage.

### Issue document by docType
When the document docType to be issued use the ``EudiWallet/issueDocument(docType:format:promptMessage:)`` method.

__Important Notes__:

- Currently, only mso_mdoc format is supported
- Currently, only ES256 algorithm is supported for signing OpenId4CVI proof of possession of the
	publicKey.

The following example shows how to issue an EUDI Personal ID document using OpenID4VCI:

```swift
wallet.openID4VciIssuerUrl = "https://issuer.eudiw.dev" 
wallet.openID4VciClientId = "wallet-dev"
wallet.openID4VciRedirectUri = "eudi-openid4ci://authorize/" 
do {
	let doc = try await userWallet.issueDocument(docType: EuPidModel.euPidDocType, format: .cbor)
	// document has been added to wallet storage, you can display it
}
catch {
	// display error
}
```
### Resolving Credential offer

The library provides the ``EudiWallet/resolveOfferUrlDocTypes(uriOffer:format:useSecureEnclave:)``   method that resolves the credential offer URI.
The method returns the resolved ``OfferedIssuanceModel`` object that contains the offer's data (offered document types, issuer name and transaction code specification for pre-authorized flow). The offer's data can be displayed to the
user.

The following example shows how to resolve a credential offer:

```swift
 func resolveOfferUrlDocTypes(uriOffer: String) async throws -> OfferedIssuanceModel {
		return try await wallet.resolveOfferUrlDocTypes(uriOffer: uriOffer)
	}
```

After user acceptance of the offer, the selected documents can be issued using the ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:format:promptMessage:useSecureEnclave:claimSet:)`` method.
The `txCodeValue` parameter is not used in the case of the authorization code flow.

The following example shows how to issue documents by offer URL:
```swift
 let documents = try await walletController.issueDocumentsByOfferUrl(offerUri: uri,  docTypes: docOffers, format: .cbor, txCodeValue: txCodeValue )
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

After user acceptance of the offer, the selected documents can be issued using the ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:format:promptMessage:useSecureEnclave:claimSet:)`` method.
When the transaction code is provided, the issuance process can be resumed by calling the above-mentioned method and passing the transaction code in the `txCodeValue` parameter.

### Dynamic issuance
Wallet kit supports the Dynamic [PID based issuance](https://github.com/eu-digital-identity-wallet/eudi-wallet-product-roadmap/issues/82)

After calling ``EudiWallet/issueDocument(docType:format:promptMessage:)`` or ``EudiWallet/issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:format:promptMessage:useSecureEnclave:claimSet:)`` the wallet application need to check if the doc is pending and has a `authorizePresentationUrl` property. If the property is present, the application should perform the OpenID4VP presentation using the presentation URL. On success, the ``EudiWallet/resumePendingIssuance(pendingDoc:webUrl:)`` method should be called with the authorization URL provided by the server.
```swift
if let urlString = newDocs.last?.authorizePresentationUrl { 
	// perform openid4vp presentation using the urlString 
	// on success call resumePendingIssuance using the authorization url  
```
