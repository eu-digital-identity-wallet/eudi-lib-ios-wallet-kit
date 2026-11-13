import Foundation
import OpenID4VCI
import SwiftyJSON
import Testing
import MdocDataModel18013
@testable import EudiWalletKit

@Suite("Credential metadata and extension coverage")
struct MetadataAndExtensionCoverageTests {
    @Test("Converts JSON scalar and nested claim values and skips protocol-only claims")
    func convertsCredentialClaims() throws {
        let json = JSON(parseJSON: #"""
        {
          "iss":"https://issuer.example",
          "aud":"wallet-client",
          "vct":"example.credential",
          "assurance_level":"high",
          "cnf":{"jwk":{"kty":"EC"}},
          "status":{"status_list":{"uri":"https://status.example/list","idx":3}},
          "_sd":["digest"],
          "_sd_alg":"sha-256",
          "issued_at":1700000000,
          "exp":1800000000,
          "enabled":true,
          "attributes":{"level":"gold"},
          "roles":["reader","admin"],
          "portrait":"AQID",
          "signature_usual_mark":"BAUG",
          "nullable":null
        }
        """#)

        let claims = try #require(json.toClaimsArray(pathPrefix: [], nil, "en")?.0)
        let byName = Dictionary(uniqueKeysWithValues: claims.map { ($0.name, $0) })

        #expect(Set(byName.keys) == ["issued_at", "exp", "enabled", "attributes", "roles", "portrait", "signature_usual_mark"])
        #expect(byName["issued_at"]?.path == ["issued_at"])
        #expect(byName["attributes"]?.children?.first?.path == ["attributes", "level"])
        #expect(byName["roles"]?.children?.map { $0.name } == ["0", "1"])
        #expect(byName["portrait"]?.dataValue == .bytes([1, 2, 3]))
        #expect(byName["signature_usual_mark"]?.dataValue == .bytes([4, 5, 6]))
        #expect(byName["enabled"]?.stringValue == "Y")
    }

    @Test("Uses claim metadata for localized labels, mandatory flags, and explicit byte types")
    func appliesClaimMetadata() throws {
        let displayNames = [
            DisplayMetadata(name: "Photo", localeIdentifier: "en", logo: nil, description: nil, backgroundColor: nil, textColor: nil),
            DisplayMetadata(name: "Foto", localeIdentifier: "de", logo: nil, description: nil, backgroundColor: nil, textColor: nil)
        ]
        let metadata = [
            DocClaimMetadata(display: displayNames, isMandatory: true, claimPath: ["photo"], valueType: "image/jpeg"),
            DocClaimMetadata(display: nil, isMandatory: false, claimPath: ["optional"], valueType: nil)
        ]
        let json = JSON(["photo": "AQID", "optional": "", "unknown": "value"])
        let claims = try #require(json.toClaimsArray(pathPrefix: [], metadata, "de")?.0)
        let photo = try #require(claims.first { $0.name == "photo" })
        let optional = try #require(claims.first { $0.name == "optional" })

        #expect(photo.displayName == "Foto")
        #expect(!photo.isOptional)
        #expect(photo.dataValue == .bytes([1, 2, 3]))
        #expect(optional.isOptional)
        #expect(optional.displayName == nil)
        #expect(claims.first { $0.name == "unknown" }?.displayName == nil)
    }

    @Test("Handles base64url padding and rejects malformed input")
    func decodesBase64Url() {
        #expect(Data(base64urlEncoded: "AQ") == Data([1]))
        #expect(Data(base64urlEncoded: "-_8") == Data([0xfb, 0xff]))
        #expect(Data(base64urlEncoded: "not valid !") == nil)
    }

    @Test("Extracts the credential issuer from valid offer URLs and rejects malformed offers")
    func extractsCredentialIssuerFromOfferUri() {
        let offer = #"{"credential_issuer":"https://issuer.example/tenant"}"#
        let encoded = offer.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        #expect(EudiWallet.extractCredentialIssuerURL(from: "openid-credential-offer://?credential_offer=\(encoded)") == "https://issuer.example/tenant")
        #expect(EudiWallet.extractCredentialIssuerURL(from: "openid-credential-offer://?credential_offer=not-json") == nil)
        #expect(EudiWallet.extractCredentialIssuerURL(from: "openid-credential-offer://?credential_offer=%7B%7D") == nil)
        #expect(EudiWallet.extractCredentialIssuerURL(from: "not a url [") == nil)
    }

    @Test("Formats the credential issuer metadata error variants")
    func formatsMetadataErrors() {
        #expect(CredentialOfferRequest.metadataErrorDescription(for: CredentialIssuerMetadataError.missingContentType("no content type")) == "no content type")
        #expect(CredentialOfferRequest.metadataErrorDescription(for: CredentialIssuerMetadataError.missingRightContentTypeHeader) == "Credential issuer metadata has an invalid Content-Type")
        #expect(CredentialOfferRequest.metadataErrorDescription(for: CredentialIssuerMetadataError.invalidSignedMetadata("bad signature")) == "Invalid signed credential issuer metadata: bad signature")
        #expect(CredentialOfferRequest.metadataErrorDescription(for: CredentialIssuerMetadataError.invalidIssuerTrust) == "Credential issuer metadata is not issued by a trusted issuer")
        #expect(CredentialOfferRequest.metadataErrorDescription(for: CredentialIssuerMetadataError.unableToFetchCredentialIssuerMetadata(cause: NSError(domain: "network", code: 7, userInfo: [NSLocalizedDescriptionKey: "offline"]))) == "Unable to fetch credential issuer metadata: offline")
        #expect(CredentialOfferRequest.metadataErrorDescription(for: CredentialIssuerMetadataError.nonParseableSignedMetadata) == "nonParseableSignedMetadata")
        #expect(CredentialOfferRequest.metadataErrorDescription(for: NSError(domain: "unknown", code: 1, userInfo: [NSLocalizedDescriptionKey: "other error"])) == "other error")
    }

    @Test("Downloads display images into inline data URLs while retaining metadata")
    func downloadsDisplayImages() async throws {
        let metadata = DocMetadata(
            credentialIssuerIdentifier: "https://issuer.example",
            configurationIdentifier: "pid",
            docType: "pid",
            display: [DisplayMetadata(
                name: "Identity card",
                localeIdentifier: "en",
                logo: LogoMetadata(urlString: "https://issuer.example/logo.png", alternativeText: "issuer logo"),
                description: "A test credential",
                backgroundColor: "#ffffff",
                textColor: "#000000",
                backgroundImageURL: "http://issuer.example/background.png"
            )],
            issuerDisplay: nil,
            claims: nil,
            authorizedRequestData: nil,
            keyOptions: nil,
            credentialOptions: nil
        )

        let downloaded = await metadata.downloadingDisplayImages(networking: DisplayImageNetworking())
        let display = try #require(downloaded.display?.first)
        let imageBytes = Data("image bytes".utf8).base64EncodedString()
        #expect(display.logo?.urlString == "data:image/png;base64,\(imageBytes)")
        #expect(display.backgroundImageURL == "data:image/png;base64,\(imageBytes)")
        #expect(display.logo?.alternativeText == "issuer logo")
        #expect(display.name == "Identity card")
        #expect(display.description == "A test credential")
    }

    @Test("Leaves unsupported and already-inline image URLs unchanged")
    func skipsUnsupportedImageUrls() async throws {
        let display = DisplayMetadata(
            name: "Identity card",
            localeIdentifier: "en",
            logo: LogoMetadata(urlString: "data:image/png;base64,AQID", alternativeText: nil),
            description: nil,
            backgroundColor: nil,
            textColor: nil,
            backgroundImageURL: "file:///tmp/background.png"
        )

        let resolved = await display.downloadingImages(networking: DisplayImageNetworking())
        #expect(resolved == display)
    }

    @Test("Keeps image URLs when the image request fails")
    func retainsImageUrlsOnFailure() async throws {
        let metadata = DocMetadata(
            credentialIssuerIdentifier: "https://issuer.example",
            configurationIdentifier: "pid",
            docType: "pid",
            display: [DisplayMetadata(
                name: "Identity card",
                logo: LogoMetadata(urlString: "https://issuer.example/logo.png", alternativeText: nil)
            )],
            issuerDisplay: nil,
            claims: nil,
            authorizedRequestData: nil,
            keyOptions: nil,
            credentialOptions: nil
        )

        let result = await metadata.downloadingDisplayImages(networking: DisplayImageNetworking(fails: true))
        #expect(result.display?.first?.logo?.urlString == "https://issuer.example/logo.png")
    }

    @Test("Detects attestation proof support only when metadata requires it")
    func resolvesProofTypeAttestationSupport() {
        let optionalJwt = ProofTypeSupportedMeta(algorithms: ["ES256"], keyAttestationRequirement: .notRequired)
        let requiredAttestation = ProofTypeSupportedMeta(algorithms: ["ES256"], keyAttestationRequirement: .requiredNoConstraints)
        let support = resolveProofTypeAttestationSupport(proofTypesSupported: [
            "jwt": optionalJwt,
            "attestation": requiredAttestation
        ])
        #expect(support.jwtProofType != nil)
        #expect(support.jwtProofTypeKeyAttestationRequirement == .notRequired)
        #expect(support.attestProofTypeKeyAttestationRequirement == .requiredNoConstraints)
        #expect(support.supportsAttestationProofType)
        #expect(!support.supportsJwtProofTypeWithAttestation)

        let jwtWithAttestation = ProofTypeSupportedMeta(algorithms: ["ES256"], keyAttestationRequirement: .requiredNoConstraints)
        let jwtSupport = resolveProofTypeAttestationSupport(proofTypesSupported: ["jwt": jwtWithAttestation])
        #expect(jwtSupport.supportsJwtProofTypeWithAttestation)
        #expect(!jwtSupport.supportsAttestationProofType)
    }
}

private struct DisplayImageNetworking: Networking {
    var fails = false

    func data(from url: URL) async throws -> (Data, URLResponse) {
        if fails { throw NSError(domain: "display-image", code: 1) }
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "image/png"])!
        return (Data("image bytes".utf8), response)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(from: request.url ?? URL(string: "https://issuer.example")!)
    }
}
