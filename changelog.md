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
