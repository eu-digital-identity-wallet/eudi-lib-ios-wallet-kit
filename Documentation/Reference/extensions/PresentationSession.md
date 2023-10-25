**EXTENSION**

# `PresentationSession`
```swift
extension PresentationSession: PresentationService
```

## Methods
### `presentAttestations()`

```swift
@discardableResult	public func presentAttestations() async throws -> [String: Any]
```

### `generateQRCode()`

```swift
public func generateQRCode() async throws -> Data?
```

### `receiveRequest()`

```swift
public func receiveRequest() async throws -> [String: Any]
```

### `sendResponse(userAccepted:itemsToSend:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
```
