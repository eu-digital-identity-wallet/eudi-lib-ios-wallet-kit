import Foundation
import MdocDataModel18013
import Testing
@testable import EudiWalletKit

@Suite("Trust Mark manager coverage")
struct TrustMarkManagerCoverageTests {
    private let resourceJSON = Data(#"{"image":{"name":"mark","url":"/mark.svg"},"text":{"name":"Certified","localisations":{"en":"Certified wallet","fr":"Portefeuille certifié"}}}"#.utf8)

    @Test("Loads Trust Mark resources from static and dynamic information")
    func loadsStaticAndDynamicTrustMark() async throws {
        let information = TrustMarkInformation(
            trustMarkResourceURL: "https://trust.example/mark",
            listOfCertifiedWalletsURL: "https://trust.example/wallets",
            walletSolutionInfoPageURL: "https://wallet.example/certification"
        )
        let staticNetwork = TrustMarkCoverageNetworking(data: resourceJSON)
        let staticMark = try await TrustMarkManager(source: .static(information: information), networking: staticNetwork).getTrustMark()
        #expect(staticMark.information == information)
        #expect(staticMark.resource.text.localizedValue(for: "fr-CA") == "Portefeuille certifié")
        #expect(await staticNetwork.requestedURL?.absoluteString == information.trustMarkResourceURL)

        let dynamicProvider = TrustMarkCoverageProvider(information: information)
        let dynamicNetwork = TrustMarkCoverageNetworking(data: resourceJSON)
        let dynamicMark = try await TrustMarkManager(source: .dynamic(provider: dynamicProvider), networking: dynamicNetwork).getTrustMark()
        #expect(dynamicMark == staticMark)
    }

    @Test("Rejects invalid resource URLs, unsuccessful HTTP responses, and malformed resources")
    func rejectsInvalidTrustMarkResponses() async {
        let information = TrustMarkInformation(
            trustMarkResourceURL: "file:///tmp/mark.json",
            listOfCertifiedWalletsURL: "https://trust.example/wallets",
            walletSolutionInfoPageURL: "https://wallet.example/certification"
        )
        do {
            _ = try await TrustMarkManager(source: .static(information: information), networking: TrustMarkCoverageNetworking(data: resourceJSON)).getTrustMark()
            Issue.record("Non-HTTP Trust Mark URLs should be rejected")
        } catch let error as URLError {
            #expect(error.code == .badURL)
        } catch {
            Issue.record("Expected URLError.badURL, received \(error)")
        }

        let validInformation = TrustMarkInformation(
            trustMarkResourceURL: "https://trust.example/mark",
            listOfCertifiedWalletsURL: "https://trust.example/wallets",
            walletSolutionInfoPageURL: "https://wallet.example/certification"
        )
        do {
            _ = try await TrustMarkManager(source: .static(information: validInformation), networking: TrustMarkCoverageNetworking(data: resourceJSON, statusCode: 503)).getTrustMark()
            Issue.record("Non-successful HTTP responses should be rejected")
        } catch let error as URLError {
            #expect(error.code == .badServerResponse)
        } catch {
            Issue.record("Expected URLError.badServerResponse, received \(error)")
        }

        do {
            _ = try await TrustMarkManager(source: .static(information: validInformation), networking: TrustMarkCoverageNetworking(data: Data("not-json".utf8))).getTrustMark()
            Issue.record("Malformed Trust Mark JSON should fail decoding")
        } catch is DecodingError {
            #expect(Bool(true))
        } catch {
            Issue.record("Expected a decoding error, received \(error)")
        }
    }

    @Test("Propagates provider and transport failures")
    func propagatesFailures() async {
        let information = TrustMarkInformation(
            trustMarkResourceURL: "https://trust.example/mark",
            listOfCertifiedWalletsURL: "https://trust.example/wallets",
            walletSolutionInfoPageURL: "https://wallet.example/certification"
        )
        do {
            let failedProvider = TrustMarkCoverageProvider(information: information, error: URLError(.notConnectedToInternet))
            _ = try await TrustMarkManager(source: .dynamic(provider: failedProvider), networking: TrustMarkCoverageNetworking(data: resourceJSON)).getTrustMark()
            Issue.record("Provider failures should propagate")
        } catch let error as URLError {
            #expect(error.code == .notConnectedToInternet)
        } catch {
            Issue.record("Expected provider error, received \(error)")
        }

        do {
            _ = try await TrustMarkManager(source: .static(information: information), networking: TrustMarkCoverageNetworking(data: resourceJSON, error: URLError(.timedOut))).getTrustMark()
            Issue.record("Transport failures should propagate")
        } catch let error as URLError {
            #expect(error.code == .timedOut)
        } catch {
            Issue.record("Expected transport error, received \(error)")
        }
    }
}

private struct TrustMarkCoverageProvider: TrustMarkProvider {
    let information: TrustMarkInformation
    var error: URLError?

    init(information: TrustMarkInformation, error: URLError? = nil) {
        self.information = information
        self.error = error
    }

    func getTrustMarkInformation() async throws -> TrustMarkInformation {
        if let error { throw error }
        return information
    }
}

private actor TrustMarkCoverageNetworking: NetworkingProtocol {
    private let data: Data
    private let statusCode: Int
    private let error: URLError?
    private(set) var requestedURL: URL?

    init(data: Data, statusCode: Int = 200, error: URLError? = nil) {
        self.data = data
        self.statusCode = statusCode
        self.error = error
    }

    func data(from url: URL) async throws -> (Data, URLResponse) {
        requestedURL = url
        if let error { throw error }
        let response = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: ["Content-Type": "application/json"] )!
        return (data, response)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        guard let url = request.url else { throw URLError(.badURL) }
        return try await data(from: url)
    }
}
