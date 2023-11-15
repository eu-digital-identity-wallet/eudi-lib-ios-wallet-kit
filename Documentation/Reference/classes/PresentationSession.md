**CLASS**

# `PresentationSession`

**Contents**

- [Properties](#properties)
  - `readerCertIssuerMessage`
  - `readerCertValidationMessage`
  - `uiError`
  - `disclosedDocuments`
  - `status`
  - `flow`
  - `deviceEngagement`
  - `notAvailable`
- [Methods](#methods)
  - `init(presentationService:)`
  - `decodeRequest(_:)`
  - `didFinishedWithError(_:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:onCancel:)`

```swift
public class PresentationSession: ObservableObject
```

Presentation session

This class wraps the ``PresentationService`` instance, providing bindable fields to a SwifUI view

## Properties
### `readerCertIssuerMessage`

```swift
@Published public var readerCertIssuerMessage: String?
```

Reader certificate issuer (only for BLE flow wih verifier using reader authentication)

### `readerCertValidationMessage`

```swift
@Published public var readerCertValidationMessage: String?
```

Reader certificate validation message (only for BLE transfer wih verifier using reader authentication)

### `uiError`

```swift
@Published public var uiError: WalletError?
```

Error message when the ``status`` is in the error state.

### `disclosedDocuments`

```swift
@Published public var disclosedDocuments: [DocElementsViewModel] = []
```

Request items selected by the user to be sent to verifier.

### `status`

```swift
@Published public var status: TransferStatus = .initializing
```

Status of the data transfer.

### `flow`

```swift
public var flow: FlowType
```

The ``FlowType`` instance

### `deviceEngagement`

```swift
@Published public var deviceEngagement: Data?
```

Device engagement data (QR image data for the BLE flow)

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

Decodes a presentation request
- Parameter request: Keys are defined in the ``UserRequestKeys``

### `didFinishedWithError(_:)`

```swift
public func didFinishedWithError(_ error: Error)
```

### `startQrEngagement()`

```swift
public func startQrEngagement() async throws
```

### `receiveRequest()`

```swift
public func receiveRequest() async throws
```

### `sendResponse(userAccepted:itemsToSend:onCancel:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onCancel: (() -> Void)?) async throws
```
