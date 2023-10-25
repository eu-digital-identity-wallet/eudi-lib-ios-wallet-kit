**CLASS**

# `FaultPresentationService`

**Contents**

- [Properties](#properties)
  - `status`
  - `flow`
  - `error`
- [Methods](#methods)
  - `init(error:)`
  - `generateQRCode()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:)`

```swift
class FaultPresentationService: PresentationService
```

## Properties
### `status`

```swift
var status: TransferStatus = .error
```

### `flow`

```swift
var flow: FlowType = .ble
```

### `error`

```swift
var error: Error
```

## Methods
### `init(error:)`

```swift
init(error: Error)
```

### `generateQRCode()`

```swift
func generateQRCode() async throws -> Data?
```

### `receiveRequest()`

```swift
func receiveRequest() async throws -> [String : Any]
```

### `sendResponse(userAccepted:itemsToSend:)`

```swift
func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
```
