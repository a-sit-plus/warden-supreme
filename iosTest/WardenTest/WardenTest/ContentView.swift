import Security
import SwiftUI
import WardenSupreme

struct ContentView: View {
    @AppStorage("challengeEndpoint") private var challengeEndpoint = "https://verifier.example/api/v1/challenge"
    @State private var alias = "warden-\(UUID().uuidString.lowercased())"
    @State private var dataToSign = "Hello from Warden Supreme"
    @State private var isAttesting = false
    @State private var result: (successful: Bool, message: String)?
    @State private var signatureResult: (successful: Bool, message: String)?

    private let client = IosAttestationClient()

    var body: some View {
        NavigationStack {
            Form {
                Section("Supreme verifier") {
                    TextField("Challenge endpoint", text: $challengeEndpoint, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)

                    Text("The challenge response supplies the attestation POST endpoint.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Attested key") {
                    TextField("Key alias", text: $alias)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    Button {
                        alias = "warden-\(UUID().uuidString.lowercased())"
                        result = nil
                        signatureResult = nil
                    } label: {
                        Label("Use new alias", systemImage: "arrow.clockwise")
                    }
                }

                Section {
                    Button(action: attest) {
                        HStack {
                            Spacer()
                            if isAttesting {
                                ProgressView()
                            } else {
                                Label("Attest key", systemImage: "checkmark.shield")
                            }
                            Spacer()
                        }
                    }
                    .disabled(isAttesting || alias.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                } footer: {
                    Text("Use HTTPS outside local development. The verifier must be configured for this app's Team ID, bundle ID, and sandbox environment.")
                }

                if let result {
                    Section("Result") {
                        Label(
                            result.message,
                            systemImage: result.successful ? "checkmark.seal.fill" : "xmark.octagon.fill"
                        )
                        .foregroundStyle(result.successful ? .green : .red)
                        .textSelection(.enabled)
                    }
                }

                Section {
                    TextField("Data to sign", text: $dataToSign, axis: .vertical)

                    Button(action: signAndVerify) {
                        Label("Sign and verify", systemImage: "signature")
                    }
                    .disabled(
                        alias.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                        dataToSign.isEmpty
                    )

                    if let signatureResult {
                        Label(
                            signatureResult.message,
                            systemImage: signatureResult.successful ? "checkmark.seal.fill" : "xmark.octagon.fill"
                        )
                        .foregroundStyle(signatureResult.successful ? .green : .red)
                        .textSelection(.enabled)
                    }
                } header: {
                    Text("Sign and verify")
                } footer: {
                    Text("Uses the private key stored by Signum and the public key from the verifier's leaf certificate.")
                }

#if targetEnvironment(simulator)
                Section {
                    Label("App Attest requires a physical iPhone.", systemImage: "iphone.gen3")
                        .foregroundStyle(.orange)
                }
#endif
            }
            .navigationTitle("Warden Supreme")
        }
    }

    private func attest() {
        guard let url = URL(string: challengeEndpoint),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil else {
            result = (false, "Enter an absolute HTTP(S) challenge URL.")
            return
        }

        isAttesting = true
        result = nil
        Task { @MainActor in
            do {
                let response = try await client.performAttestation(
                    alias: alias,
                    challengeEndpoint: url
                )
                isAttesting = false
                result = (response.successful, response.message)
            } catch {
                isAttesting = false
                result = (false, error.localizedDescription)
            }
        }
    }

    private func signAndVerify() {
        Task { @MainActor in
            do {
                let privateKey = try await client.getAttestedKey(alias: alias)

                guard let certificate = client.getAttestationKeyCertificate(alias: alias) else {
                    throw DemoError("No verifier certificate stored for alias '\(alias)'. Attest it first.")
                }
                guard let publicKey = SecCertificateCopyKey(certificate) else {
                    throw DemoError("The leaf certificate contains no supported public key.")
                }

                let algorithm = [
                    SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                    .rsaSignatureMessagePSSSHA256,
                    .rsaSignatureMessagePKCS1v15SHA256,
                ].first {
                    SecKeyIsAlgorithmSupported(privateKey, .sign, $0) &&
                    SecKeyIsAlgorithmSupported(publicKey, .verify, $0)
                }
                guard let algorithm else {
                    throw DemoError("The attested key does not support an expected SHA-256 signature algorithm.")
                }

                let data = Data(dataToSign.utf8) as CFData
                var signingError: Unmanaged<CFError>?
                guard let signature = SecKeyCreateSignature(privateKey, algorithm, data, &signingError) else {
                    throw signingError?.takeRetainedValue() ?? DemoError("Signing failed.")
                }

                var verificationError: Unmanaged<CFError>?
                let verified = SecKeyVerifySignature(publicKey, algorithm, data, signature, &verificationError)
                if !verified, let error = verificationError?.takeRetainedValue() {
                    throw error
                }
                signatureResult = (
                    verified,
                    verified ? "Signature verified against the leaf certificate." : "Signature verification failed."
                )
            } catch {
                signatureResult = (false, error.localizedDescription)
            }
        }
    }
}

private struct DemoError: LocalizedError {
    let errorDescription: String?

    init(_ message: String) {
        errorDescription = message
    }
}
