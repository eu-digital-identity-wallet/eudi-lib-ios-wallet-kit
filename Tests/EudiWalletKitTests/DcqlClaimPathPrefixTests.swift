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

import Testing
import Foundation
import OpenID4VP
@testable import EudiWalletKit

struct DcqlClaimPathPrefixTests {
  private let placeOfBirth = ClaimPath([.claim(name: "place_of_birth")])
  private let country = ClaimPath([.claim(name: "place_of_birth"), .claim(name: "country")])
  private let locality = ClaimPath([.claim(name: "place_of_birth"), .claim(name: "locality")])

  private var queryable: DefaultDcqlQueryable {
    DefaultDcqlQueryable(credentials: ["pid": ("urn:eudi:pid:1", .sdjwt)], claimPaths: ["pid": [placeOfBirth, country]])
  }

  @Test func longerPathDoesNotContainShorterPath() {
    #expect(placeOfBirth.contains2(locality))
    #expect(!locality.contains2(placeOfBirth))
    #expect(!locality.contains2(country))
  }

  @Test func missingNestedClaimIsNotFound() {
    #expect(queryable.hasClaim(id: "pid", claimPath: country))
    #expect(queryable.hasClaim(id: "pid", claimPath: placeOfBirth))
    #expect(!queryable.hasClaim(id: "pid", claimPath: locality))
  }

  @Test func claimSetsSelectFirstOptionTheCredentialHas() throws {
    let data = Data(#"{"credentials":[{"id":"my_credential","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"id":"pob_locality","path":["place_of_birth","locality"]},{"id":"pob_region","path":["place_of_birth","region"]},{"id":"pob_country","path":["place_of_birth","country"]}],"claim_sets":[["pob_locality"],["pob_region"],["pob_country"]]}]}"#.utf8)
    let query = try JSONDecoder().decode(DCQL.self, from: data)
    let claims = try OpenId4VpUtils.resolveClaimsForCredential(credQuery: query.credentials[0], credId: "pid", queryable: queryable)
    #expect(claims.map(\.path) == [country])
  }
}
