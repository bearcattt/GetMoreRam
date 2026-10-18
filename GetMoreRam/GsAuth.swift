//
//  GsAuth.swift
//  GetMoreRam
//
//  Faithful port of rileytestut/AltSign PR #61 (832d9ce) — "Send GrandSlam
//  requests with the anisette provider's client identity" — combined with
//  altstoreio/AltStore PR #1835 (Windows-anisette provisioning + hsc-434
//  resync + hsc-409 code-already-sent), adapted to await/async and to
//  StosSign's public API (GSAContext, AppleAPISession, AppleAPIError).
//
//  Ported to GetMoreRam after research found Apple's Oct 12–14 2026
//  rules from:
//  - https://github.com/rileytestut/AltSign/pull/61
//  - https://github.com/altstoreio/AltStore/pull/1835
//

import Foundation
import StosSign_API
import StosSign_Auth
import StosSign_Common

/// GrandSlam authentication exactly as AltSign PR #61 implements it.
enum GsAuth {
    // MARK: - Configuration

    /// The User-Agent sent with GrandSlam requests. It must match the client
    /// that generated the anisette data (anisette v3 servers report it in
    /// /v3/client_info). Defaults to akd's user agent.
    static var authenticationUserAgent: String {
        AnisetteDataHelper.shared.userAgent ?? "akd/1.0 CFNetwork/808.1.4"
    }

    /// Fresh anisette provider (Apple rejects one-time passwords that were
    /// already used, so ask for fresh anisette data before each step that
    /// follows the first sign-in). App wires this to the anisette helper.
    static var anisetteDataRefreshHandler: (() async throws -> AnisetteData)?

    /// Called when GrandSlam answers hsc 434 (anisette data out of sync) with
    /// the X-Apple-I-MD-DATA value it returned. The handler should
    /// resynchronize the anisette provider and return fresh anisette data.
    static var anisetteDataResyncHandler: ((String) async throws -> AnisetteData)?

    // MARK: - Logs

    /// Diagnostic logging hook (LoginViewModel surfaces these in the UI).
    static var logHandler: ((String) -> Void)?

    private static func log(_ text: String) {
        print("[GsAuth]", text)
        logHandler?(text)
    }

    // MARK: - Session plumbing

    /// Don't follow redirects for GrandSlam requests so an unexpected
    /// redirect surfaces as an HTTP error.
    private final class AuthenticationSessionDelegate: NSObject, URLSessionTaskDelegate {
        static let shared = AuthenticationSessionDelegate()

        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }

    private static var authenticationSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpMaximumConnectionsPerHost = 1
        return URLSession(configuration: configuration,
                          delegate: AuthenticationSessionDelegate.shared,
                          delegateQueue: nil)
    }()

    // MARK: - Public entry point

    /// Public API identical in shape to StosSign's `AppleAPI.authenticate`.
    static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        verificationHandler: ((@escaping (String?) -> Void) async -> Void)? = nil
    ) async throws -> (Account, AppleAPISession) {
        let sanitizedAppleID = unsanitizedAppleID.lowercased()

        let context = GSAContext(username: sanitizedAppleID, password: password)
        guard let A2k = context.start() else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        func beginAuthentication(using anisetteData: AnisetteData, hasResynchronized: Bool = false) async throws -> (Account, AppleAPISession) {
            let clientDictionary = makeClientDictionary(anisetteData: anisetteData)
            let parameters: [String: Any] = [
                "A2k": A2k,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": sanitizedAppleID
            ]

            let (responseDictionary, statusDictionary) = try await sendAuthenticationRequest(
                parameters: parameters,
                anisetteData: anisetteData
            )

            // hsc 434: anisette data out of sync — resynchronize once and retry.
            if statusDictionary["hsc"] as? Int == 434 {
                guard !hasResynchronized, let resync = anisetteDataResyncHandler else {
                    throw AppleAPIError.invalidAnisetteData
                }
                let sim = (statusDictionary["X-Apple-I-MD-DATA"] as? String)
                    ?? (statusDictionary["X-Apple-I-MD-DATA"] as? Data)?.base64EncodedString()
                guard let sim, !sim.isEmpty else {
                    throw AppleAPIError.invalidAnisetteData
                }
                let fresh = try await resync(sim)
                return try await beginAuthentication(using: fresh, hasResynchronized: true)
            }

            guard let c = responseDictionary["c"] as? String,
                  let salt = responseDictionary["s"] as? Data,
                  let iterations = responseDictionary["i"] as? Int,
                  let B = responseDictionary["B"] as? Data
            else {
                throw AppleAPIError.badServerResponse
            }

            context.salt = salt
            context.serverPublicKey = B

            let sp = responseDictionary["sp"] as? String
            let isHexadecimal = (sp == "s2k_fo")

            guard let verificationMessage = context.makeVerificationMessage(
                iterations: iterations,
                isHexadecimal: isHexadecimal
            ) else {
                throw AppleAPIError.authenticationHandshakeFailed
            }

            let verificationParameters: [String: Any] = [
                "c": c,
                "cpd": clientDictionary,
                "M1": verificationMessage,
                "o": "complete",
                "u": sanitizedAppleID
            ]

            let (verificationResponse, verificationStatus) = try await sendAuthenticationRequest(
                parameters: verificationParameters,
                anisetteData: anisetteData
            )

            guard let M2 = verificationResponse["M2"] as? Data,
                  let spd = verificationResponse["spd"] as? Data
            else {
                throw AppleAPIError.badServerResponse
            }

            let status = verificationStatus

            guard context.verifyServerVerificationMessage(M2) else {
                throw AppleAPIError.authenticationHandshakeFailed
            }

            guard let decryptedData = spd.decryptedCBC(context: context) else {
                throw AppleAPIError.authenticationHandshakeFailed
            }

            guard let decryptedDictionary = try PropertyListSerialization.propertyList(
                from: decryptedData,
                format: nil
            ) as? [String: Any],
                  let dsid = decryptedDictionary["adsid"] as? String,
                  let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
            else {
                throw AppleAPIError.badServerResponse
            }

            context.dsid = dsid

            func signInAgain() async throws -> (Account, AppleAPISession) {
                // One-time passwords are single-use: refresh before re-signing.
                let fresh = try await refreshAnisetteData(from: anisetteData)
                return try await authenticate(
                    appleID: unsanitizedAppleID,
                    password: password,
                    anisetteData: fresh,
                    verificationHandler: verificationHandler
                )
            }

            // Since October 2026 Apple often sends the code to trusted devices
            // on its own, answering with hsc 409 and no "au" value.
            let authType = status["au"] as? String
            let isCodeAlreadySent = (authType ?? "").isEmpty && status["hsc"] as? Int == 409

            switch isCodeAlreadySent ? "trustedDeviceSecondaryAuth" : authType {
            case "trustedDeviceSecondaryAuth":
                guard let verificationHandler = verificationHandler else {
                    throw AppleAPIError.requiresTwoFactorAuthentication
                }

                try await requestTrustedDeviceTwoFactorCode(
                    dsid: dsid,
                    idmsToken: idmsToken,
                    anisetteData: anisetteData,
                    isCodeAlreadySent: isCodeAlreadySent,
                    verificationHandler: verificationHandler
                )

                return try await signInAgain()

            case "secondaryAuth":
                guard let verificationHandler = verificationHandler else {
                    throw AppleAPIError.requiresTwoFactorAuthentication
                }

                try await requestSMSTwoFactorCode(
                    dsid: dsid,
                    idmsToken: idmsToken,
                    anisetteData: anisetteData,
                    verificationHandler: verificationHandler
                )

                return try await signInAgain()

            default:
                guard let sessionKey = decryptedDictionary["sk"] as? Data,
                      let c = decryptedDictionary["c"] as? Data
                else {
                    throw AppleAPIError.badServerResponse
                }

                context.sessionKey = sessionKey

                let app = "com.apple.gs.xcode.auth"
                guard let checksum = context.makeChecksum(appName: app) else {
                    throw AppleAPIError.authenticationHandshakeFailed
                }

                // One-time passwords are single-use: fetch fresh anisette data
                // before requesting the token.
                let fresh = try await refreshAnisetteData(from: anisetteData)

                let tokenParameters: [String: Any] = [
                    "app": [app],
                    "c": c,
                    "checksum": checksum,
                    "cpd": makeClientDictionary(anisetteData: fresh),
                    "o": "apptokens",
                    "t": idmsToken,
                    "u": dsid
                ]

                let token = try await fetchAuthToken(
                    app: app,
                    parameters: tokenParameters,
                    context: context,
                    anisetteData: fresh
                )

                let session = AppleAPISession(dsid: dsid, authToken: token, anisetteData: fresh)
                let account = try await AppleAPI.shared.fetchAccount(session: session)
                return (account, session)
            }
        }

        return try await beginAuthentication(using: anisetteData)
    }

    // MARK: - Helpers (copied from the PR)

    private static func makeClientDictionary(anisetteData: AnisetteData) -> [String: Any] {
        [
            "bootstrap": "true",
            "icscrec": "true",
            "pbe": "false",
            "prkgen": "true",
            "svct": "iCloud",
            "loc": "en_US",
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier
        ]
    }

    private static func refreshAnisetteData(from anisetteData: AnisetteData) async throws -> AnisetteData {
        guard let handler = anisetteDataRefreshHandler else { return anisetteData }
        return try await handler()
    }

    private static func fetchAuthToken(
        app: String,
        parameters: [String: Any],
        context: GSAContext,
        anisetteData: AnisetteData
    ) async throws -> String {
        let (responseDictionary, _) = try await sendAuthenticationRequest(
            parameters: parameters,
            anisetteData: anisetteData
        )

        guard let et = responseDictionary["et"] as? Data else {
            throw AppleAPIError.badServerResponse
        }

        guard let tokenData = et.decryptedGCM(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        guard let tokensDictionary = try PropertyListSerialization.propertyList(
            from: tokenData,
            format: nil
        ) as? [String: Any] else {
            throw AppleAPIError.badServerResponse
        }

        guard let appTokens = tokensDictionary["t"] as? [String: Any],
              let tokens = appTokens[app] as? [String: Any],
              let authToken = tokens["token"] as? String
        else {
            throw AppleAPIError.badServerResponse
        }

        return authToken
    }

    // MARK: - Requests

    private static func sendAuthenticationRequest(
        parameters requestParameters: [String: Any],
        anisetteData: AnisetteData
    ) async throws -> (response: [String: Any], status: [String: Any]) {
        let requestURL = URL(string: "https://gsa.apple.com/grandslam/GsService2")!

        let parameters: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": requestParameters
        ]

        let httpHeaders = [
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "Accept": "text/x-xml-plist",
            "X-Xcode-Version": "27.0 (27A5218g)",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "Connection": "close",
            "User-Agent": authenticationUserAgent
        ]

        let bodyData = try PropertyListSerialization.data(
            fromPropertyList: parameters,
            format: .xml,
            options: 0
        )

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }

        let (data, response) = try await authenticationSession.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let httpStatus = httpResponse?.statusCode ?? 0

        // Stem diagnostics before parsing: operation + HTTP result.
        let operation = (requestParameters["o"] as? String) ?? "?"
        log("GSA \(operation): HTTP \(httpStatus)")

        // GSA answers rejected clients with an HTML error page (e.g. 503),
        // which would otherwise surface as a plist parsing error.
        guard (200 ..< 300).contains(httpStatus) else {
            let bodyPrefix = String(data: data.prefix(200), encoding: .utf8) ?? "<\(data.count) bytes>"
            log("GSA \(operation): rejected body: \(bodyPrefix)")
            throw AppleAPIError.customError(code: httpStatus, message: "GSA returned HTTP \(httpStatus): \(bodyPrefix)")
        }

        guard let responseDictionary = try? PropertyListSerialization.propertyList(
            from: data,
            format: nil
        ) as? [String: Any],
              let dictionary = responseDictionary["Response"] as? [String: Any],
              let status = dictionary["Status"] as? [String: Any]
        else {
            let bodyPrefix = String(data: data.prefix(200), encoding: .utf8) ?? "<\(data.count) bytes>"
            log("GSA \(operation): non-plist/missing Response body: \(bodyPrefix)")
            throw AppleAPIError.badServerResponse
        }
        if let hsc = status["hsc"] as? Int {
            log("GSA \(operation): hsc \(hsc) ec \(status["ec"] as? Int ?? 0) em \(status["em"] as? String ?? "")")
        }

        // hsc 434 (anisette out of sync) is handled by the caller via the
        // resync handler — don't try to interpret "ec" here.
        guard status["hsc"] as? Int != 434 else {
            return (dictionary, status)
        }

        // Map Apple's error codes to typed errors (AltSign PR #61 semantics).
        let errorCode = status["ec"] as? Int ?? 0
        if errorCode != 0 {
            switch errorCode {
            case -20970, -20101, -22406:
                throw AppleAPIError.incorrectCredentials
            case -22421:
                throw AppleAPIError.invalidAnisetteData
            case -20209:
                throw AppleAPIError.accountLocked
            default:
                throw AppleAPIError.customError(
                    code: errorCode,
                    message: (status["em"] as? String ?? "Unknown error") + " (\(errorCode))"
                )
            }
        }


        return (dictionary, status)
    }

    private static func makeTwoFactorCodeRequest(
        url: URL,
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData
    ) -> URLRequest {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentityToken = identityToken.data(using: .utf8)?.base64EncodedString() ?? ""

        let httpHeaders = [
            "Accept": "text/x-xml-plist",
            "X-Xcode-Version": "27.0 (27A5218g)",
            "Connection": "close",
            "Accept-Language": "en-us",
            "Content-Type": "text/x-xml-plist",
            "User-Agent": authenticationUserAgent,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": ISO8601DateFormatter().string(from: anisetteData.date),
            "X-Apple-Locale": anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation() ?? "PST"
        ]

        var request = URLRequest(url: url)
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }

        return request
    }

    private static func requestTrustedDeviceTwoFactorCode(
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        isCodeAlreadySent: Bool,
        verificationHandler: @escaping (@escaping (String?) -> Void) async -> Void
    ) async throws {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        let verifyURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!

        // Asking for another code here would invalidate the one Apple already sent.
        if !isCodeAlreadySent {
            let request = makeTwoFactorCodeRequest(
                url: requestURL,
                dsid: dsid,
                idmsToken: idmsToken,
                anisetteData: anisetteData
            )
            _ = try await authenticationSession.data(for: request)
        }

        let verificationCode: String? = try await withCheckedThrowingContinuation { continuation in
            Task {
                await verificationHandler { code in
                    continuation.resume(returning: code)
                }
            }
        }

        guard let code = verificationCode else {
            throw AppleAPIError.requiresTwoFactorAuthentication
        }

        // Typing the code can take longer than the one-time password stays
        // valid, so fetch fresh anisette data first.
        let fresh = try await refreshAnisetteData(from: anisetteData)

        var verifyRequest = makeTwoFactorCodeRequest(
            url: verifyURL,
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: fresh
        )
        verifyRequest.allHTTPHeaderFields?["security-code"] = code

        let (data, response) = try await authenticationSession.data(for: verifyRequest)
        let httpResponse = response as? HTTPURLResponse
        guard let httpStatus = httpResponse?.statusCode, (200 ..< 300).contains(httpStatus) else {
            throw AppleAPIError.customError(code: httpResponse?.statusCode ?? 0,
                                            message: "Could not verify the code: HTTP \(httpResponse?.statusCode ?? 0)")
        }

        guard let responseDictionary = try PropertyListSerialization.propertyList(
            from: data,
            format: nil
        ) as? [String: Any] else {
            throw AppleAPIError.badServerResponse
        }

        let errorCode = responseDictionary["ec"] as? Int ?? 0
        guard errorCode == 0 else {
            switch errorCode {
            case -21669:
                throw AppleAPIError.incorrectVerificationCode
            default:
                guard let errorDescription = responseDictionary["em"] as? String else {
                    throw AppleAPIError.unknown
                }
                throw AppleAPIError.customError(
                    code: errorCode,
                    message: "\(errorDescription) (\(errorCode))"
                )
            }
        }
    }

    private static func requestSMSTwoFactorCode(
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        verificationHandler: @escaping (@escaping (String?) -> Void) async -> Void
    ) async throws {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=sms")!
        let verifyURL = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!

        var request = makeTwoFactorCodeRequest(
            url: requestURL,
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: anisetteData
        )
        request.httpMethod = "POST"

        let bodyXML: [String: Any] = [
            "serverInfo": [
                "phoneNumber.id": "1"
            ]
        ]

        request.httpBody = try PropertyListSerialization.data(
            fromPropertyList: bodyXML,
            format: .xml,
            options: 0
        )

        _ = try await authenticationSession.data(for: request)

        let verificationCode: String? = try await withCheckedThrowingContinuation { continuation in
            Task {
                await verificationHandler { code in
                    continuation.resume(returning: code)
                }
            }
        }

        guard let code = verificationCode else {
            throw AppleAPIError.requiresTwoFactorAuthentication
        }

        var verifyRequest = makeTwoFactorCodeRequest(
            url: verifyURL,
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: anisetteData
        )
        verifyRequest.httpMethod = "POST"

        let verifyBodyXML: [String: Any] = [
            "securityCode.code": code,
            "serverInfo": [
                "mode": "sms",
                "phoneNumber.id": "1"
            ]
        ]

        verifyRequest.httpBody = try PropertyListSerialization.data(
            fromPropertyList: verifyBodyXML,
            format: .xml,
            options: 0
        )

        let (_, response) = try await authenticationSession.data(for: verifyRequest)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200,
              httpResponse.allHeaderFields.keys.contains("X-Apple-PE-Token")
        else {
            throw AppleAPIError.incorrectVerificationCode
        }
    }
}
