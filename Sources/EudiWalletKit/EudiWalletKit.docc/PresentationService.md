#  Presentation Service

The library supports document presentation via BLE (proximity) or online verifier (remote).

The ``PresentationService`` protocol abstracts the presentation flow. The ``BlePresentationService`` and ``OpenId4VpService`` classes implement the proximity and remote presentation flows respectively. The ``PresentationSession`` class is used to wrap the presentation service and provide `@Published` properties for SwiftUI screens. The following example code demonstrates the initialization of a SwiftUI view with a new presentation session of a selected ``FlowType``.

```swift
let session = eudiWallet.beginPresentation(flow: flow)
// pass the session to a SwiftUI view
ShareView(presentationSession: session)
```

## BLE Transfer Mode

For proximity presentation over BLE, the ``EudiWallet/bleTransferMode`` property controls the role the holder device plays during BLE data transfer.
Set it through ``EudiWalletConfiguration/bleTransferMode`` during initialization, or change it on the wallet instance before starting a BLE presentation:

- **`.server`** (default): The holder device acts as a GATT peripheral (server). It advertises and waits for the reader to connect.
- **`.client`**: The holder device acts as a GATT central (client). It scans and connects to the reader's peripheral.
- **`.both`**: The holder device supports both peripheral server and central client modes simultaneously, advertising the supported modes in the device engagement QR code.

```swift
let config = EudiWalletConfiguration(
    bleTransferMode: .server  // default
)
let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), fallbackTrustSource: nil)
let wallet = try! EudiWallet(eudiWalletConfig: config, trustConfig: trustConfig)
wallet.bleTransferMode = .both
```

## BLE Transport Factory

The ``EudiWallet/bleTransportFactory`` property allows you to inject a custom BLE transport implementation for proximity presentation. This is useful when you need to use alternative BLE communication channels such as L2CAP or a custom BLE client mdoc transport.

The factory conforms to the `BleTransportFactory` protocol, which requires two methods:
- `createServer()` – returns a transport instance acting as a GATT peripheral (server).
- `createClient()` – returns a transport instance acting as a GATT central (client).

When no factory is provided (the default), `DefaultBleTransportFactory` is used, which creates standard GATT server and central transports from the `MdocDataTransfer18013` library.

You can set the factory during initialization via ``EudiWalletConfiguration/bleTransportFactory`` or assign it directly on the wallet instance before starting a BLE presentation:

```swift
// Custom factory example
struct L2CAPTransportFactory: BleTransportFactory {
    func createServer() -> any MdocBleTransport {
        // return your custom L2CAP server transport
    }
    func createClient() -> any MdocBleTransport {
        // return your custom L2CAP client transport
    }
}

// Set via configuration
let config = EudiWalletConfiguration(
    bleTransferMode: .server,
    bleTransportFactory: L2CAPTransportFactory()
)
let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef),fallbackTrustSource: nil)
let wallet = try! EudiWallet(eudiWalletConfig: config, trustConfig: trustConfig)
```

```swift
// Or set directly on the wallet instance
wallet.bleTransportFactory = L2CAPTransportFactory()
```

```swift
let session = eudiWallet.beginPresentation(flow: flow)
// pass the session to a SwiftUI view
ShareView(presentationSession: session)
```

The wallet can also override the response mode requested by the verifier using ``OpenId4VpConfiguration/preferredResponseMode``. Set it to ``PreferredResponseMode/directPost`` to send the authorization response as a plain POST, or ``PreferredResponseMode/directPostJWT`` to send it as an encrypted direct POST JWT. The response URI is always taken from the verifier's request. When `nil` (the default), the library uses the response mode from the verifier's request.

```swift
let openId4VpConfig = OpenId4VpConfiguration(
    clientIdSchemes: [.x509SanDns, .x509Hash, .redirectUri],
    preferredResponseMode: .directPostJWT
)
let wallet = try! EudiWallet(
    eudiWalletConfig: config,
    openID4VpConfig: openId4VpConfig
)
```

On view appearance the attestations are presented with the ``PresentationService/receiveRequest()`` method. For the BLE (proximity) case, the ``PresentationSession/deviceEngagement`` property is populated with the QR code to be displayed on the holder device.

```swift
.task {
  if presentationSession.flow.isProximity { await presentationSession.startQrEngagement() }
  _ = await presentationSession.receiveRequest()
}
```

## Credential Selection

After the request is received, ``PresentationSession/disclosedDocumentSets`` contains an array of ``DisclosedDocumentSet`` values. Each set holds the matching documents (`docElements`) and any registration-policy `warnings` for that combination. When credential sets or the `multiple` flag produce multiple satisfiable combinations, the UI should allow the user to pick which option to present.

Each ``DisclosedDocumentSet`` carries per-option ``PresentationPolicyViolation`` warnings raised during WRPRC validation (see <doc:RegistrationCertificate>). These indicate over-asked claims or other policy violations specific to that credential combination and should be surfaced to the user.

When partial-claim presentation is enabled, each option includes only the claims that are both requested and available. The selected state of the items can be modified via UI binding.

The `deviceNameSpacesToSend` parameter allows including device-signed namespaces in the response. Pass a ``RequestDeviceNameSpaces`` value when device namespaces are needed, or omit it to send only issuer-signed data.

```swift
// Example: use the first credential selection option
let selectedOption = presentationSession.disclosedDocumentSets.first
let items = selectedOption?.docElements ?? []
let warnings = selectedOption?.warnings ?? []

// Send the disclosed document items after biometric authentication (FaceID or TouchID)
// if the user cancels biometric authentication, onCancel method is called
await presentationSession.sendResponse(userAccepted: true,
  itemsToSend: items.items, onCancel: { dismiss() }, onSuccess: {
    if let url = $0 {
      // handle URL
    }
  })
```

## QES transaction data

Enable the CSC QES transaction types explicitly in the OpenID4VP configuration:

```swift
let configuration = OpenId4VpConfiguration(
    supportedTransactionDataTypes: [.qesRequest, .qesApprovalRequest]
)
```

The identifiers are `https://cloudsignatureconsortium.org/2025/qes` and
`https://cloudsignatureconsortium.org/2025/qes-approval`. The default configuration accepts no
transaction data types. Other explicitly configured types are exposed as raw JSON.

Each disclosed document set exposes `transactionData`, keyed by wallet document ID. Display
**all** transactions in the chosen option before asking for consent. The array preserves multiple
transactions of the same type. Use `DisclosedDocumentSet.transactionData` as the source of
transaction information for the consent UI.

```swift
for transactions in selectedOption.transactionData.values {
    for transaction in transactions {
        switch transaction.payload {
        case .qesApprovalRequest(let approval):
            // Display signatureQualifier, numSignatures and every document digest/label.
            showApproval(approval)
        case .qesRequest(let request):
            showSignatureRequests(request.signatureRequests)
        case .raw(let json):
            showCustomTransaction(json)
        }
    }
}
try await presentationSession.sendResponse(
    userAccepted: true,
    itemsToSend: selectedOption.docElements.items,
    requestName: selectedOption.requestName
)
```

Pass `requestName` to preserve the displayed option's transaction and credential-query assignment.
Without it, ambiguous transaction assignments are rejected. Each transaction is bound to exactly
one eligible credential, following `credential_ids` order. QES approvals support both SD-JWT VC
and mdoc. SD-JWTs need a holder binding key; mdocs need a device key and issuer `KeyAuthorizations`
permitting `org.cloudsignatureconsortium.dm.1/qesApproval` (the entire namespace or that element).
Options that cannot authorize every transaction are not offered.

The Key Binding JWT hashes the original encoded transaction string, using a mutually supported
hash algorithm (SHA-256 by default; SHA-384 and SHA-512 can be configured). A QES approval also
adds `org.cloudsignatureconsortium.dm.1.qesApproval`, using `hashAlgorithmOID` and standard Base64
as required by CSC. Multiple approvals that would need the same proof are rejected. This library
does not fetch referenced documents or perform the remote signing operation; those belong to
the application and RQES libraries.

For mdoc, the wallet automatically includes `qesApproval` in the device-signed namespace
`org.cloudsignatureconsortium.dm.1`. Following [CSC Data Model Bindings §7.2.1.1](https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf),
the value is a CBOR byte string containing SHA-256 of the original **decoded JSON bytes**,
without reserialization or Base64 encoding of the digest. This binding does not use the SD-JWT
`transaction_data_hashes_alg` negotiation or its `hashAlgorithmOID`-selected approval hash.
Other application-supplied device namespaces are preserved; a conflicting `qesApproval` is rejected.
The generated response must contain the device-signed approval; a ZK-only response cannot replace it.
Only `qesApprovalRequest` has a supported mdoc binding. `qesRequest` and custom types cannot be
assigned to an mdoc without a format-specific binding and return `invalid_transaction_data`
when no supported alternative credential can authorize them.

Malformed, unsupported or unfulfillable transaction data produces `WalletError.Code.invalidTransactionData`
(`invalid_transaction_data`) and a protocol error response when safe dispatch details are available.
The other OpenID4VP error codes are exposed as distinct wallet codes, including `invalidScope`,
`invalidRequest`, `invalidClient`, `accessDenied`, `vpFormatsNotSupported`, `invalidRequestUriMethod`
and `walletUnavailable`. Credential matching failures retain their detailed wallet codes and send
`access_denied` to the verifier. Negative consent works even when the request omits `state`.

Presentation log entries retain decoded objects in `transactionalData` alongside the result,
including declined requests. Read typed payloads with
`entry.transactionalData?.payloads(supportedTypes: configuration.supportedTransactionDataTypes)`.
Older log entries without transaction data remain readable.
