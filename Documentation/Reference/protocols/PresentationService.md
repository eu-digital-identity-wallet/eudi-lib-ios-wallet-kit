**PROTOCOL**

# `PresentationService`

```swift
public protocol PresentationService
```

Presentation service abstract protocol

## Properties
### `flow`

```swift
var flow: FlowType
```

instance of a presentation ``FlowType``

## Methods
### `startQrEngagement()`

```swift
func startQrEngagement() async throws -> String?
```

Generate a QR code to be shown to verifier (optional)

### `receiveRequest()`

```swift
func receiveRequest() async throws -> [String: Any]
```

- Returns: The requested items.
Receive request.

### `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws
```

Send response to verifier
- Parameters:
  - userAccepted: True if user accepted to send the response
  - itemsToSend: The selected items to send organized in document types and namespaces (see ``RequestItems``)

#### Parameters

| Name | Description |
| ---- | ----------- |
| userAccepted | True if user accepted to send the response |
| itemsToSend | The selected items to send organized in document types and namespaces (see `RequestItems`) |