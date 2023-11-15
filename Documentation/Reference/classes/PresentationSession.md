**CLASS**

# `PresentationSession`

**Contents**

- [Properties](#properties)
  - `presentationService`
  - `readerCertIssuer`
  - `readerCertValidationMessage`
  - `uiError`
  - `disclosedDocuments`
  - `status`
  - `flow`
  - `deviceEngagement`
- [Methods](#methods)
  - `init(presentationService:)`
  - `decodeRequest(_:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:onCancel:)`

```swift
public class PresentationSession: ObservableObject
```

Presentation session

This class wraps the ``PresentationService`` instance, providing bindable fields to a SwifUI view

## Properties
### `presentationService`

```swift
public var presentationService: any PresentationService
```

### `readerCertIssuer`

```swift
@Published public var readerCertIssuer: String?
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

The ``disclosedDocuments`` property will be set. Additionally ``readerCertIssuer`` and ``readerCertValidationMessage`` may be set for the BLE proximity flow
- Parameter request: Keys are defined in the ``UserRequestKeys``

### `startQrEngagement()`

```swift
public func startQrEngagement() async
```

Start QR engagement to be presented to verifier

On success ``deviceEngagement`` published variable will be set with the result and ``status`` will be ``.qrEngagementReady``
On error ``uiError`` will be filled and ``status`` will be ``.error``

### `receiveRequest()`

```swift
public func receiveRequest() async -> [String: Any]?
```

Receive request from verifer

The request is futher decoded internally. See also ``decodeRequest(_:)``
On success ``disclosedDocuments`` published variable will be set  and ``status`` will be ``.requestReceived``
On error ``uiError`` will be filled and ``status`` will be ``.error``
- Returns: A request dictionary keyed by ``MdocDataTransfer.UserRequestKeys``

### `sendResponse(userAccepted:itemsToSend:onCancel:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onCancel: (() -> Void)?) async
```

Send response to verifier
- Parameters:
  - userAccepted: Whether user confirmed to send the response
  - itemsToSend: Data to send organized into a hierarcy of doc.types and namespaces
  - onCancel: Action to perform if the user cancels the biometric authentication
