//
//  LoginViewModel.swift
//  GetMoreRam
//
//  Created by s s on 2025/3/15.
//
import SwiftUI
import StosSign_API
import StosSign_Auth
import StosSign_Common

@MainActor
class LoginViewModel: ObservableObject {
    @Published var appleID = ""
    @Published var password = ""
    @Published var needVerificationCode = false
    @Published var verificationCode = ""
    @Published var loginModalShow = false
    @Published var teamSelectionShow = false
    @Published var isLoginInProgress = false
    @Published private(set) var isVerificationCodeSubmitting = false
    @Published var logs = ""
    @Published var availableTeams: [Team] = []

    /// Async handler handed to us by StosSign while it waits for a 2FA code.
    private var pendingVerificationInner: ((String?) async -> Void)?
    private var verificationCodeContinuation: CheckedContinuation<String?, Never>?
    private var isAuthenticationCancellationRequested = false

    func submitVerificationCode() {
        guard !isVerificationCodeSubmitting,
              let verificationCodeContinuation else { return }

        self.verificationCodeContinuation = nil
        isVerificationCodeSubmitting = true

        let code = verificationCode.trimmingCharacters(in: .whitespacesAndNewlines)
        let cancelled = isAuthenticationCancellationRequested
        let inner = pendingVerificationInner
        pendingVerificationInner = nil

        Task {
            await inner?(cancelled || code.isEmpty ? nil : code)
            verificationCodeContinuation.resume(returning: cancelled || code.isEmpty ? nil : code)
        }
    }

    func cancelAuthentication() {
        guard isLoginInProgress else { return }

        isAuthenticationCancellationRequested = true

        needVerificationCode = false
        verificationCode = ""
        isVerificationCodeSubmitting = false

        // If we're currently waiting for a 2FA code, wake the task up with nil.
        if let verificationCodeContinuation {
            self.verificationCodeContinuation = nil
            self.pendingVerificationInner = nil
            verificationCodeContinuation.resume(returning: nil)
        }
    }

    func authenticate() async throws -> Bool {
        if isLoginInProgress {
            return false
        }

        logs = ""
        isLoginInProgress = true
        isAuthenticationCancellationRequested = false

        func logging(text: String) {
            Task { @MainActor [weak self] in
                self?.logs.append("\(text)\n")
            }
        }

        AnisetteDataHelper.shared.loggingFunc = logging

        defer {
            pendingVerificationInner = nil
            verificationCodeContinuation = nil
            appleID = ""
            password = ""
            needVerificationCode = false
            verificationCode = ""
            isLoginInProgress = false
            isVerificationCodeSubmitting = false
            isAuthenticationCancellationRequested = false
        }

        do {
            let anisetteData = try await AnisetteDataHelper.shared.getAnisetteData()

            let (account, session) = try await AppleAPI.shared.authenticate(
                appleID: appleID,
                password: password,
                anisetteData: anisetteData
            ) { inner in
                guard let self else {
                    await inner(nil)
                    return
                }

                let code = await self.requestVerificationCode(with: inner)
                await inner(code)
            }

            guard !isAuthenticationCancellationRequested else {
                throw CancellationError()
            }

            logging(text: "Successfully signed in")

            DataManager.shared.model.account = account
            DataManager.shared.model.session = session
            Keychain.shared.appleIDEmailAddress = appleID
            Keychain.shared.appleIDPassword = password

            let teams = try await fetchTeams(for: account, session: session)
            logging(text: "Successfully fetched teams")
            availableTeams = teams

            return true
        } catch {
            if isAuthenticationCancellationRequested {
                throw CancellationError()
            }
            print(error)
            throw error
        }
    }

    /// Stores StosSign's code-receiver, shows the 2FA entry sheet and
    /// suspends until the user types a code (or cancels).
    private func requestVerificationCode(with inner: @escaping (String?) async -> Void) async -> String? {
        self.pendingVerificationInner = inner

        return await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            guard !isAuthenticationCancellationRequested else {
                continuation.resume(returning: nil)
                return
            }

            self.verificationCodeContinuation = continuation
            self.verificationCode = ""
            self.needVerificationCode = true
            self.isVerificationCodeSubmitting = false
        }
    }

    private func fetchTeams(for account: Account, session: AppleAPISession) async throws -> [Team]
    {

        let fetchedTeams = try await AppleAPI.shared.fetchTeamsForAccount(account: account, session: session)
        guard !fetchedTeams.isEmpty else {
            throw "Unable to Fetch Team!"
        }

        return fetchedTeams
    }
}
