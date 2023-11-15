**CLASS**

# `EudiWallet`

**Contents**

- [Properties](#properties)
  - `storage`
  - `standard`
  - `userAuthenticationRequired`
  - `trustedReaderCertificates`
- [Methods](#methods)
  - `issueDocument(id:issuer:)`
  - `loadSampleData(sampleDataFiles:)`
  - `beginPresentation(flow:docType:dataFormat:)`
  - `authorizedAction(isFallBack:dismiss:action:)`

```swift
public final class EudiWallet: ObservableObject
```

User wallet implementation

## Properties
### `storage`

```swift
public private(set) var storage: StorageModel
```

### `standard`

```swift
public static private(set) var standard: EudiWallet = EudiWallet()
```

### `userAuthenticationRequired`

```swift
public var userAuthenticationRequired: Bool
```

### `trustedReaderCertificates`

```swift
public var trustedReaderCertificates: [Data]?
```

## Methods
### `issueDocument(id:issuer:)`

```swift
public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> WalletStorage.Document) async throws
```

### `loadSampleData(sampleDataFiles:)`

```swift
public func loadSampleData(sampleDataFiles: [String]? = nil) throws
```

### `beginPresentation(flow:docType:dataFormat:)`

```swift
public func beginPresentation(flow: FlowType, docType: String? = nil, dataFormat: DataFormat = .cbor) -> PresentationSession
```

Begin attestation presentation to a verifier
- Parameters:
  - flow: Presentation ``FlowType`` instance
  - dataFormat: Exchanged data ``Format`` type
- Returns: A presentation session instance,

#### Parameters

| Name | Description |
| ---- | ----------- |
| flow | Presentation `FlowType` instance |
| dataFormat | Exchanged data `Format` type |

### `authorizedAction(isFallBack:dismiss:action:)`

```swift
public static func authorizedAction(isFallBack: Bool = false, dismiss: () -> Void, action: () async throws -> Void) async throws
```
