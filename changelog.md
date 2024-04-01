## v.0.2.9
- Fixed MAC validation error for mDL document type

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
