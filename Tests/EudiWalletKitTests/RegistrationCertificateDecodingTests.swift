import Foundation
import MdocDataModel18013
import Testing
@testable import EudiWalletKit

struct RegistrationCertificateDecodingTests {
    @Test("Raw and base64url-encoded compact JWTs produce the same serialized certificate")
    func jwtEncoding() throws {
        let jwt = Data("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJycCJ9.AQID".utf8)
        #expect(SerializedRegistrationCertificate.decode(String(decoding: jwt, as: UTF8.self)) == jwt)
        #expect(SerializedRegistrationCertificate.decode(jwt.base64URLEncodedString()) == jwt)
        #expect(SerializedRegistrationCertificate.decode(jwt.base64EncodedString()) == jwt)
    }

    @Test("Binary CWT bytes survive URL-safe characters and missing padding")
    func cwtEncoding() {
        // COSE_Sign1: protected header, empty unprotected map, payload, signature.
        let cwt = Data([0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x41, 0x7B, 0x42, 0xFB, 0xFF])
        let encoded = cwt.base64URLEncodedString()
        #expect(encoded.contains("-") || encoded.contains("_"))
        #expect(!encoded.contains("="))
        #expect(cwt.base64EncodedString().contains("="))
        #expect(SerializedRegistrationCertificate.decode(encoded) == cwt)
        #expect(SerializedRegistrationCertificate.decode(cwt.base64EncodedString()) == cwt)
    }

    @Test("Malformed encoded certificates are rejected", arguments: ["", "☃", "a", "a.b", "!!!!", "ZXlK\n"])
    func malformedEncoding(value: String) {
        #expect(SerializedRegistrationCertificate.decode(value) == nil)
    }
}
