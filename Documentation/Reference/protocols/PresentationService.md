**PROTOCOL**

# `PresentationService`

```swift
public protocol PresentationService
```

## Properties
### `status`

```swift
var status: TransferStatus
```

### `flow`

```swift
var flow: FlowType
```

## Methods
### `generateQRCode()`

```swift
func generateQRCode() async throws -> Data?
```

### `receiveRequest()`

```swift
func receiveRequest() async throws -> [String: Any]
```

### `sendResponse(userAccepted:itemsToSend:)`

```swift
func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
```
