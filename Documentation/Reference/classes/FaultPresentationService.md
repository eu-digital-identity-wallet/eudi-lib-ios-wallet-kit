**CLASS**

# `FaultPresentationService`

**Contents**

- [Properties](#properties)
  - `status`
  - `flow`
  - `error`
- [Methods](#methods)
  - `init(error:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:)`

```swift
class FaultPresentationService: PresentationService
```

Fault presentation service. Used to communicate error state to the user

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

### `startQrEngagement()`

```swift
func startQrEngagement() async throws -> Data?
```

### `receiveRequest()`

```swift
func receiveRequest() async throws -> [String : Any]
```

### `sendResponse(userAccepted:itemsToSend:)`

```swift
func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
```

#### Parameters

| Name | Description |
| ---- | ----------- |
| userAccepted | True if user accepted to send the response |
| itemsToSend | The selected items to send organized in document types and namespaces (see `RequestItems`) |