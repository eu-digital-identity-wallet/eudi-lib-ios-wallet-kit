**CLASS**

# `OpenId4VpService`

**Contents**

- [Properties](#properties)
  - `status`
  - `flow`
- [Methods](#methods)
  - `init(parameters:qrCode:openId4VpVerifierApiUri:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
public class OpenId4VpService: PresentationService
```

Implements remote attestation presentation to online verifier
Implementation is based on the OpenID4VP – Draft 18 specification

## Properties
### `status`

```swift
public var status: TransferStatus = .initialized
```

### `flow`

```swift
public var flow: FlowType
```

## Methods
### `init(parameters:qrCode:openId4VpVerifierApiUri:)`

```swift
public init(parameters: [String: Any], qrCode: Data, openId4VpVerifierApiUri: String?) throws
```

### `startQrEngagement()`

```swift
public func startQrEngagement() async throws -> String?
```

### `receiveRequest()`

```swift
public func receiveRequest() async throws -> [String: Any]
```

 Receive request from an openid4vp URL

- Returns: The requested items.

### `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws
```

Send response via openid4vp

- Parameters:
  - userAccepted: True if user accepted to send the response
  - itemsToSend: The selected items to send organized in document types and namespaces

#### Parameters

| Name | Description |
| ---- | ----------- |
| userAccepted | True if user accepted to send the response |
| itemsToSend | The selected items to send organized in document types and namespaces |