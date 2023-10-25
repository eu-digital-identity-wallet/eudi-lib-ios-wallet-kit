**CLASS**

# `PresentationSession`

**Contents**

- [Properties](#properties)
  - `presentationService`
  - `readerCertIsserMessage`
  - `readerCertValidationMessage`
  - `errorMessage`
  - `selectedRequestItems`
  - `status`
  - `flow`
  - `handleSelected`
  - `deviceEngagement`
  - `notAvailable`
- [Methods](#methods)
  - `init(presentationService:)`
  - `decodeRequest(_:)`
  - `didFinishedWithError(_:)`
  - `makeError(str:)`

```swift
public class PresentationSession: ObservableObject
```

## Properties
### `presentationService`

```swift
var presentationService: any PresentationService
```

### `readerCertIsserMessage`

```swift
@Published public var readerCertIsserMessage: String?
```

### `readerCertValidationMessage`

```swift
@Published public var readerCertValidationMessage: String?
```

### `errorMessage`

```swift
@Published public var errorMessage: String = ""
```

### `selectedRequestItems`

```swift
@Published public var selectedRequestItems: [DocElementsViewModel] = []
```

### `status`

```swift
@Published public var status: TransferStatus = .initializing
```

### `flow`

```swift
public var flow: FlowType
```

### `handleSelected`

```swift
public var handleSelected: ((Bool, RequestItems?) -> Void)?
```

### `deviceEngagement`

```swift
@Published public var deviceEngagement: Data?
```

### `notAvailable`

```swift
public static var notAvailable: PresentationSession
```

## Methods
### `init(presentationService:)`

```swift
public init(presentationService: any PresentationService)
```

### `decodeRequest(_:)`

```swift
public func decodeRequest(_ request: [String: Any])
```

### `didFinishedWithError(_:)`

```swift
public func didFinishedWithError(_ error: Error)
```

### `makeError(str:)`

```swift
public static func makeError(str: String) -> NSError
```
