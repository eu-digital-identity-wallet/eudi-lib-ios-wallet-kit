**CLASS**

# `BlePresentationService`

**Contents**

- [Properties](#properties)
  - `status`
  - `flow`
- [Methods](#methods)
  - `init(parameters:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
public class BlePresentationService : PresentationService
```

Implements proximity attestation presentation with QR to BLE data transfer
Implementation is based on the ISO/IEC 18013-5 specification

## Properties
### `status`

```swift
public var status: TransferStatus = .initializing
```

### `flow`

```swift
public var flow: FlowType
```

## Methods
### `init(parameters:)`

```swift
public init(parameters: [String: Any]) throws
```

### `startQrEngagement()`

```swift
public func startQrEngagement() async throws -> String?
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

### `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)? ) async throws
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