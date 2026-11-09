import Testing
import Foundation
@testable import EudiWalletKit

/// Decoding of the WRPRC payload into `WrpRegistrationPolicy`.
struct WrpRegistrationPolicyDecodingTests {

	/// Payload of a WRPRC issued by the German registrar for the EUDI Wallet Playground.
	/// `srv_description` is an array of arrays, as ETSI TS 119 475 Annex B.2.1 defines `serviceDescription`.
	static let playgroundPayload = """
	{
	  "name": "sprind",
	  "sub_ln": "sprind",
	  "sub": "NTRDE-1BF324C6727B4AAA",
	  "country": "DE",
	  "registry_uri": "https://catalogue.eudi-wallet.dev/api",
	  "srv_description": [[{"lang": "en", "value": "Club"}]],
	  "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
	  "privacy_policy": "https://example.com/privacy",
	  "info_uri": "https://catalogue.eudi-wallet.dev/api",
	  "support_uri": "https://example.com/support",
	  "supervisory_authority": {
	    "email": "poststelle@bfdi.bund.de",
	    "phone": "+49 (0)228-997799-0",
	    "uri": "https://www.bfdi.bund.de/EN/Home/home_node.html"
	  },
	  "iat": 1790683413,
	  "status": {"status_list": {"idx": 9974, "uri": "https://catalogue.eudi-wallet.dev/api/status-management/status-list"}},
	  "purpose": [
	    {"lang": "en", "value": "We just need your age to enter the club."},
	    {"lang": "de", "value": "Wir brauchen nur dein Alter für den Club."}
	  ],
	  "credentials": [{"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:de:1"]}, "claim": [{"path": ["age_equal_or_over", "16"]}]}],
	  "jti": "fc06d23b-56a8-4c29-ad75-fc2632c001b7"
	}
	"""

	@Test func decodesServiceDescriptionAsArrayOfMultiLangStrings() throws {
		let policy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: Data(Self.playgroundPayload.utf8))

		let services = try #require(policy.srvDescriptions)
		#expect(services.count == 1)
		#expect(services.first?.map(\.lang) == ["en"])
		#expect(services.first?.map(\.value) == ["Club"])
	}

	@Test func decodesTheRestOfThePolicyAlongsideServiceDescription() throws {
		let policy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: Data(Self.playgroundPayload.utf8))

		#expect(policy.credentials?.count == 1)
		#expect(policy.supervisoryAuthority?.uri == "https://www.bfdi.bund.de/EN/Home/home_node.html")
		#expect(policy.purpose?.count == 2)
	}
}
