/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import OpenID4VP

/// Binds both dependency authenticators to the requested, explicitly configured client.
struct WalletAuthorizationRequestResolver: AuthorizationRequestResolving {
    private let resolver = AuthorizationRequestResolver()

    func resolve(
        walletConfiguration: OpenId4VPConfiguration,
        unvalidatedRequest: UnvalidatedRequest,
        fetcher: any Fetching,
        poster: any Posting
    ) async -> AuthorizationRequest {
        do {
            let clientId: String? = switch unvalidatedRequest {
            case .plain(let request): request.clientId
            case .jwtSecuredPassByValue(let clientId, _): clientId
            case .jwtSecuredPassByReference(let clientId, _, _): clientId
            }
            guard let clientId, !clientId.isEmpty else { throw ValidationError.missingClientId }
            let verifierId = try VerifierId.parse(clientId: clientId).get()
            // The dependency parser can discard empty leading prefix components.
            // Do not authenticate one identifier and bind the response to another.
            guard verifierId.clientId == clientId else { throw ValidationError.invalidClientId }
            let schemes = walletConfiguration.supportedClientIdSchemes
            let selected: SupportedClientIdPrefix
            if verifierId.scheme == .preRegistered {
                // Unknown prefixes can be valid preregistered IDs. Match the whole ID,
                // and pass only its key configuration to avoid dictionary-order selection.
                let clients = schemes.compactMap { scheme -> PreregisteredClient? in
                    guard case .preregistered(let clients) = scheme,
                          let client = clients[clientId], client.clientId == clientId else { return nil }
                    return client
                }
                guard clients.count == 1, let client = clients.first else {
                    throw ValidationError.validationError("Client identifier must match exactly one preregistered client")
                }
                selected = .preregistered(clients: [clientId: client])
            } else {
                guard let scheme = schemes.first(where: { $0.scheme == verifierId.scheme }) else {
                    throw ValidationError.unsupportedClientIdScheme(clientId)
                }
                selected = scheme
            }
            // Preserve the request configuration, narrowing only authentication routing.
            let configuration = OpenId4VPConfiguration(
                privateKey: walletConfiguration.privateKey,
                issuer: walletConfiguration.issuer,
                publicWebKeySet: walletConfiguration.publicWebKeySet,
                supportedClientIdSchemes: [selected],
                vpFormatsSupported: walletConfiguration.vpFormatsSupported,
                jarConfiguration: walletConfiguration.jarConfiguration,
                vpConfiguration: walletConfiguration.vpConfiguration,
                errorDispatchPolicy: walletConfiguration.errorDispatchPolicy,
                session: walletConfiguration.session,
                responseEncryptionConfiguration: walletConfiguration.responseEncryptionConfiguration,
                registrationCertificatePolicy: walletConfiguration.registrationCertificatePolicy
            )
            return await resolver.resolve(walletConfiguration: configuration, unvalidatedRequest: unvalidatedRequest,
                fetcher: fetcher, poster: poster)
        } catch {
            return .invalidResolution(
                error: (error as? AuthorizationRequestError) ?? ValidationError.validationError(error.localizedDescription),
                dispatchDetails: nil
            )
        }
    }
}
