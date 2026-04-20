#  Presentation Service

The library supports document presentation via BLE (proximity) or online verifier (remote).

The ``PresentationService`` protocol abstracts the presentation flow. The ``BlePresentationService`` and ``OpenId4VpService`` classes implement the proximity and remote presentation flows respectively. The ``PresentationSession`` class is used to wrap the presentation service and provide `@Published` properties for SwiftUI screens. The following example code demonstrates the initialization of a SwiftUI view with a new presentation session of a selected ``FlowType``.

```swift
let session = eudiWallet.beginPresentation(flow: flow)
// pass the session to a SwiftUI view
ShareView(presentationSession: session)
```

For OpenID4VP flows, partial DCQL claim presentation can be enabled through ``OpenId4VpConfiguration``. When ``OpenId4VpConfiguration/allowPresentingPartialClaims`` is `true`, claims that are not present in an otherwise matching credential are omitted instead of causing the presentation request to fail.

```swift
let openId4VpConfig = OpenId4VpConfiguration(
    clientIdSchemes: [.x509SanDns, .x509Hash, .redirectUri],
    allowPresentingPartialClaims: true
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

After the request is received the ``PresentationSession/disclosedDocuments`` contains the requested attested items that can be satisfied by the selected credential. When partial-claim presentation is enabled, this includes only the claims that are both requested and available. The selected state of the items can be modified via UI binding. Finally, the response is sent with the following code: 

```swift
// Send the disclosed document items after biometric authentication (FaceID or TouchID)
// if the user cancels biometric authentication, onCancel method is called
await presentationSession.sendResponse(userAccepted: true,
  itemsToSend: presentationSession.disclosedDocuments.items, onCancel: { dismiss() }, onSuccess: {
    if let url = $0 {
      // handle URL
    }
  })
```
