**CLASS**

# `BlePresentationService`

**Contents**

- [Properties](#properties)
  - `bleServerTransfer`
  - `status`
  - `continuationQrCode`
  - `continuationRequest`
  - `continuationResponse`
  - `handleSelected`
  - `deviceEngagement`
  - `request`
  - `flow`
- [Methods](#methods)
  - `init(parameters:)`
  - `generateQRCode()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:)`

```swift
class BlePresentationService : PresentationService
```

## Properties
### `bleServerTransfer`

```swift
var bleServerTransfer: MdocGattServer
```

### `status`

```swift
var status: TransferStatus = .initializing
```

### `continuationQrCode`

```swift
var continuationQrCode: CheckedContinuation<Data?, Error>?
```

### `continuationRequest`

```swift
var continuationRequest: CheckedContinuation<[String: Any], Error>?
```

### `continuationResponse`

```swift
var continuationResponse: CheckedContinuation<Void, Error>?
```

### `handleSelected`

```swift
var handleSelected: ((Bool, RequestItems?) -> Void)?
```

### `deviceEngagement`

```swift
var deviceEngagement: Data?
```

### `request`

```swift
var request: [String: Any]?
```

### `flow`

```swift
var flow: FlowType
```

## Methods
### `init(parameters:)`

```swift
public init(parameters: [String: Any]) throws
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
