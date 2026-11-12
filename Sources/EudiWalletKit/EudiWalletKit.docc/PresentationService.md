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

## Reader Authentication and Certificate Trust

Use ``PresentationSession/readerAuthenticationStatus`` to display authentication of the current request.

| Status | Meaning |
| --- | --- |
| `.notEvaluated` | Authentication has not completed or no result is available. |
| `.authenticated` | The request passed the authentication required by its client identifier scheme. For X.509 clients, the reader certificate chain is also trusted. |
| `.authenticatedWithUntrustedCertificate` | The request signature was verified, but the reader certificate chain is untrusted and was accepted under an explicit warning policy. |
| `.failed` | Request validation or required authentication failed. |
| `.notApplicable` | The flow, such as plain redirect URI, requires no reader authentication. |

``TrustConfiguration/readerTrustPolicy`` controls access certificate trust for OpenID4VP `.x509SanDns` and `.x509Hash` clients. The default, `.enforce`, rejects untrusted chains. To allow valid signed requests with an untrusted chain:

```swift
let trustConfig = TrustConfiguration(
    trustSource: .etsi(.eudiRef),
    readerTrustPolicy: .warning
)
```

The warning policy still requires a well-formed certificate chain, an evaluated leaf matching the request's signing certificate, and a valid request signature. It does not change BLE reader authentication, issuer trust policies, or WRPRC validation policies.

When the status is `.authenticatedWithUntrustedCertificate`, display a certificate trust warning using ``PresentationSession/readerCertValidationMessage`` and do not show a trusted-reader badge. ``PresentationSession/readerLegalName`` remains `nil` for this status. The session permits sending a response after the request has otherwise passed validation and the user has made a consent decision. Update exhaustive switches over ``ReaderAuthenticationStatus`` to handle the new case explicitly.

## Credential Selection

After the request is received, ``PresentationSession/disclosedDocumentSets`` contains an array of ``DisclosedDocumentSet`` values. Each set represents a presentation option, with matching documents (`docElements`), an option identifier (`requestName`), and registration-policy `warnings`. When there are several satisfiable options, let the user choose which option to present.

For a DCQL query with `multiple: true`, an option contains all matching credentials for that query. The application can let the user choose a subset of those credentials, for example by showing document-level checkboxes when several stored PIDs or attestations match. Credential selection is separate from selecting which claims to disclose within a document.

### Query metadata

Use the following properties of ``DisclosedDocumentSet`` to build the selection UI:

| Property | Meaning |
| --- | --- |
| `credentialSelections` | Maps each wallet document's `credentialId` to every `queryId` it answers through `queryIds`. A document can answer more than one query. |
| `credentialQueries` | Exposes each represented query's `queryId`, `multiple`, and `required` constraints within this option. |
| `credentialSets` | Preserves the original DCQL credential-set alternatives and their `required` flags, when present. |
| `requestName` | Identifies the option to use when sending the selected documents. |

A query's `required` value indicates whether removing it would leave a required credential set unsatisfied within this option. For grouped alternatives, consult `credentialSets`: individual queries can be optional while the group still requires one complete alternative. When no credential sets are supplied, every requested query is required. Query metadata is empty and `credentialSets` is `nil` for proximity presentations.

Use document IDs and query IDs to associate checkboxes with queries; do not group credentials solely by document type, because different queries can request the same type. Preserve all query associations when one document answers several queries.

Each ``DisclosedDocumentSet`` carries per-option ``PresentationPolicyViolation`` warnings raised during WRPRC validation (see <doc:RegistrationCertificate>). These indicate over-asked claims or other policy violations specific to that credential combination and should be surfaced to the user.

When partial-claim presentation is enabled, each option includes only the claims that are both requested and available. The selected state of the items can be modified via UI binding. Preserve those claim selections when the user checks or unchecks a document.

### Sending the selected credentials

Pass the selected documents' items and the option's `requestName` to `sendResponse`. The following example assumes `selectedDocumentIds` contains the wallet document IDs chosen by the user:

```swift
// Use the option chosen by the user.
let selectedOption = presentationSession.disclosedDocumentSets[selectedOptionIndex]
let selectedDocuments = selectedOption.docElements.filter {
    selectedDocumentIds.contains($0.docId)
}

// Send after biometric authentication (FaceID or TouchID).
// If the user cancels authentication, onCancel is called.
try await presentationSession.sendResponse(
    userAccepted: true,
    itemsToSend: selectedDocuments.items,
    requestName: selectedOption.requestName,
    onCancel: { dismiss() },
    onSuccess: { url in
        if let url {
            // Handle the verifier's redirect URL.
        }
    }
)
```

To send the entire option, use `selectedOption.docElements.items` with the same `requestName`. The optional `deviceNameSpacesToSend` parameter accepts a ``RequestDeviceNameSpaces`` value for application-supplied device namespaces.

For accepted OpenID4VP responses, the kit validates the selection before signing:

- The selection must be non-empty and contain only documents from the named option.
- A `multiple: true` query accepts a subset of its matching credentials, provided required credential sets remain satisfied.
- A query without `multiple: true` cannot receive more than one credential.
- Every selected document retains its query IDs, including when several queries request the same document type.

Invalid credential selections throw `WalletError` with code `.invalidRequest`. Disable the consent button while required selections are missing and surface response errors to the user. Without `requestName`, the submitted document IDs must match an entire option and have unambiguous query associations; pass the name whenever the user selects a subset.

Declining consent still uses `userAccepted: false` with empty `itemsToSend`.

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

Each disclosed document set exposes `transactionData`, keyed by the initially assigned wallet document ID. Display
**all** transactions in the chosen option before asking for consent. The array preserves multiple
transactions of the same type. Use `DisclosedDocumentSet.transactionData` as the source of
transaction information for the consent UI. Do not hide transactions when the user deselects a document that was initially assigned to authorize them.

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

Pass `requestName` to identify the displayed option and preserve its credential-query associations.
When sending a subset, use `selectedDocuments.items` as in the credential-selection example.
Before signing, the kit reassigns all transaction data to eligible documents actually selected for
sending. Each transaction is bound to exactly one eligible credential, following `credential_ids`
order. If the selected subset cannot authorize every transaction, the response fails with
`WalletError.Code.invalidTransactionData`. QES approvals support both SD-JWT VC
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
