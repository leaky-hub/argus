// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Never compiled; exists only to be scanned by semgrep.
//
// Swift LANDED via the curated local ruleset (argus/curated): the registry
// packs (p/swift, p/default) caught none of the plants below, so each is
// covered by a hand-written rule in internal/scanner/rules/curated.yaml,
// proven by TestProfileRecall. .swift counts as SAST-covered in skip
// accounting. Safe-code counterparts live in fp/safe.swift.

import Foundation
import CommonCrypto

func takeInput() -> String {
    return CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
}

// PLANT(swift-sqli, min-profile=standard, CWE-89): SQL built by string interpolation (caught by argus/curated)
func sqli(userInput: String, db: OpaquePointer?) {
    let query = "SELECT * FROM users WHERE name = '\(userInput)'"
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(db, query, -1, &stmt, nil)
}

// PLANT(swift-weak-hash, min-profile=standard, CWE-328): MD5 over sensitive input (caught by argus/curated)
func weakHash(userInput: String) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    let data = Array(userInput.utf8)
    CC_MD5(data, CC_LONG(data.count), &digest)
    return digest
}

// PLANT(swift-tls-verify, min-profile=standard, CWE-295): TLS certificate validation disabled (caught by argus/curated)
final class TrustAll: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let cred = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, cred)
    }
}

// PLANT(swift-cmdi, min-profile=standard, CWE-78): Process invoking a shell with concatenated input (caught by argus/curated)
func runShell(userInput: String) {
    let task = Process()
    task.launchPath = "/bin/sh"
    task.arguments = ["-c", "echo " + userInput]
    try? task.run()
}

// PLANT(swift-hardcoded-secret, min-profile=standard, CWE-798): hardcoded credential (caught by argus/curated)
let apiKey = "AKIAIOSFODNN7EXAMPLE"

func main() {
    let input = takeInput()
    sqli(userInput: input, db: nil)
    _ = weakHash(userInput: input)
    runShell(userInput: input)
    _ = apiKey
}
