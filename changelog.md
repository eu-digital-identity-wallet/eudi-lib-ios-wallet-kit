## v0.3.9
OpenID4VCI: Allow partial issuing when some documents fail to issue

## v0.3.8
OpenID4VCI: Fixed issuing with https://dev.issuer.eudiw.dev

## v0.3.7
### Added functions:
/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached

` public func resolveOfferUrlDocTypes(uriOffer: String, format: DataFormat = .cbor, useSecureEnclave: Bool = true) async throws -> [OfferedDocModel] `

/// Issue documents by offer URI.

`public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], format: DataFormat, promptMessage: String? = nil, useSecureEnclave: Bool = true, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] `

### Breaking change: 
 `// PresentationSession
 @Published public var deviceEngagement: String?`
    use the following code to convert to QR code image:  
    
 `let qrImage =  DeviceEngagement.getQrCodeImage(qrCode: d)`

## v0.3.6
Updated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.74
Updated `eudi-lib-ios-openid4vci-swift` to v0.0.7

## v0.3.5
Updated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.73
Updated `eudi-lib-ios-openid4vci-swift` to v0.0.6

## v0.3.4
- Refactor MdocDecodable (DocType, DocumentIdentifier, createdAt), 

## v0.3.3
- OpenID4VP draft 13 support

## v0.3.2
- Internal updates for security checks

## v0.3.1
- Updated presentation definition parsing

## v0.3.0
- Updated eudi-lib-ios-siop-openid4vp-swift to 0.0.72

## v0.2.9
- Fixed mDOC authentication MAC validation error for mDL document type

## v0.1.7
- Added delete documents func
- Storage manager functions are now `async throws`
### MdocDataModel18013
- extractDisplayStrings is recursive (cbor elements can be dictionaries)
- NameValue: added `var children: [NameValue]` property (tree-like structure)
- MdocDecodable: added 'var displayImages: [NameImage]' property

## v0.1.6
- Add isMandatory property to DocElementsViewModel structure
- `PresentationSession` methods do not run on main actor
- `PresentationSession`: add `readerCertIssuerValid`` (is verifier certificate trusted)
- `PresentationSession`: change `readerCertIssuer`` (has verifier certificate common name)
- `MdocDecodable`: add extension method: `public func toJson() -> [String: Any]`
