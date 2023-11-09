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
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:)`

```swift
class BlePresentationService : PresentationService
```

Implements proximity attestation presentation with QR to BLE data transfer
Implementation is based on the ISO/IEC 18013-5 specification

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

### `startQrEngagement()`

```swift
public func startQrEngagement() async throws -> Data?
```

Generate device engagement QR code 
The holder app should present the returned code to the verifier
- Returns: The image data for the QR code

### `receiveRequest()`

```swift
public func receiveRequest() async throws -> [String: Any]
```

 Receive request via BLE

- Returns: The requested items.

### `sendResponse(userAccepted:itemsToSend:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
```

Send response via BLE

- Parameters:
  - userAccepted: True if user accepted to send the response
  - itemsToSend: The selected items to send organized in document types and namespaces

#### Parameters

| Name | Description |
| ---- | ----------- |
| userAccepted | True if user accepted to send the response |
| itemsToSend | The selected items to send organized in document types and namespaces |