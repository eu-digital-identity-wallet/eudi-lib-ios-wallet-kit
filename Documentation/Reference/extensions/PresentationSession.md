**EXTENSION**

# `PresentationSession`
```swift
extension PresentationSession: PresentationService
```

## Methods
### `startQrEngagement()`

```swift
public func startQrEngagement() async throws -> Data?
```

### `receiveRequest()`

```swift
public func receiveRequest() async throws -> [String: Any]
```

### `sendResponse(userAccepted:itemsToSend:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
```

#### Parameters

| Name | Description |
| ---- | ----------- |
| userAccepted | True if user accepted to send the response |
| itemsToSend | The selected items to send organized in document types and namespaces (see `RequestItems`) |