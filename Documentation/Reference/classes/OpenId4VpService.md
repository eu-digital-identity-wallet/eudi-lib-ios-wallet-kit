**CLASS**

# `OpenId4VpService`

**Contents**

- [Properties](#properties)
  - `status`
  - `openid4VPlink`
  - `docs`
  - `iaca`
  - `devicePrivateKey`
  - `logger`
  - `presentationDefinition`
  - `resolvedRequestData`
  - `siopOpenId4Vp`
  - `flow`
  - `walletConf`
- [Methods](#methods)
  - `init(parameters:qrCode:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:)`
  - `parsePresentationDefinition(_:)`

```swift
class OpenId4VpService: PresentationService
```

Implements remote attestation presentation to online verifier
Implementation is based on the OpenID4VP – Draft 18 specification

## Properties
### `status`

```swift
var status: TransferStatus = .initialized
```

### `openid4VPlink`

```swift
var openid4VPlink: String
```

### `docs`

```swift
var docs: [DeviceResponse]!
```

### `iaca`

```swift
var iaca: [SecCertificate]!
```

### `devicePrivateKey`

```swift
var devicePrivateKey: CoseKeyPrivate!
```

### `logger`

```swift
var logger = Logger(label: "OpenId4VpService")
```

### `presentationDefinition`

```swift
var presentationDefinition: PresentationDefinition?
```

### `resolvedRequestData`

```swift
var resolvedRequestData: ResolvedRequestData?
```

### `siopOpenId4Vp`

```swift
var siopOpenId4Vp: SiopOpenID4VP!
```

### `flow`

```swift
var flow: FlowType
```

### `walletConf`

```swift
static var walletConf: WalletOpenId4VPConfiguration? = {
	let VERIFIER_API = ProcessInfo.processInfo.environment["VERIFIER_API"] ?? "http://localhost:8080"
	let verifierMetaData = PreregisteredClient(clientId: "Verifier", jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(VERIFIER_API)/wallet/public-keys.json")!))
	guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
		  let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
	guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
	guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
	var res = WalletOpenId4VPConfiguration(subjectSyntaxTypesSupported: [], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), idTokenTTL: 10 * 60, presentationDefinitionUriSupported: true, signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])], vpFormatsSupported: [])
	return res
}()
```

OpenId4VP wallet configuration

## Methods
### `init(parameters:qrCode:)`

```swift
init(parameters: [String: Any], qrCode: Data) throws
```

### `startQrEngagement()`

```swift
func startQrEngagement() async throws -> Data?
```

### `receiveRequest()`

```swift
func receiveRequest() async throws -> [String: Any]
```

 Receive request from an openid4vp URL

- Returns: The requested items.

### `sendResponse(userAccepted:itemsToSend:)`

```swift
func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws
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

### `parsePresentationDefinition(_:)`

```swift
func parsePresentationDefinition(_ presentationDefinition: PresentationDefinition) -> RequestItems?
```

Parse mDoc request from presentation definition (Presentation Exchange 2.0.0 protocol)
