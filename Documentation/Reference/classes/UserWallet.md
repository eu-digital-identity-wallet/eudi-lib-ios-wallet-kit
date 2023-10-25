**CLASS**

# `UserWallet`

**Contents**

- [Properties](#properties)
  - `storageService`
- [Methods](#methods)
  - `init(storageService:)`
  - `beginPresentation(flow:dataFormat:)`

```swift
public class UserWallet: ObservableObject
```

## Properties
### `storageService`

```swift
public var storageService: any DataStorageService
```

## Methods
### `init(storageService:)`

```swift
public init(storageService: any DataStorageService = KeyChainStorageService())
```

### `beginPresentation(flow:dataFormat:)`

```swift
public func beginPresentation(flow: FlowType, dataFormat: DataFormat = .cbor) -> PresentationSession
```
