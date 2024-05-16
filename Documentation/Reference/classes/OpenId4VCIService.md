**CLASS**

# `OpenId4VCIService`

**Contents**

- [Methods](#methods)
  - `issueDocument(docType:format:useSecureEnclave:)`
  - `presentationAnchor(for:)`

```swift
public class OpenId4VCIService: NSObject, ASWebAuthenticationPresentationContextProviding
```

## Methods
### `issueDocument(docType:format:useSecureEnclave:)`

```swift
public func issueDocument(docType: String, format: DataFormat, useSecureEnclave: Bool = true) async throws -> Data
```

Issue a document with the given `docType` using OpenId4Vci protocol
- Parameters:
  - docType: the docType of the document to be issued
  - format: format of the exchanged data
  - useSecureEnclave: use secure enclave to protect the private key
- Returns: The data of the document

#### Parameters

| Name | Description |
| ---- | ----------- |
| docType | the docType of the document to be issued |
| format | format of the exchanged data |
| useSecureEnclave | use secure enclave to protect the private key |

### `presentationAnchor(for:)`

```swift
public func presentationAnchor(for session: ASWebAuthenticationSession)
-> ASPresentationAnchor
```
