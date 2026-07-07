// Safe-code plants for the FP measurement eval (see fp/safe.py header).
// PLANT-FP(id, CWE) marks the correct, non-vulnerable form of a weakness
// class; flagging it is a measured false positive.

import Foundation
import CommonCrypto

// PLANT-FP(swift-safe-sql, CWE-89): constant statement with a "?" placeholder,
// value bound separately; nothing dynamic reaches the SQL text.
func safeQuery(db: OpaquePointer?, name: String) {
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, nil)
    sqlite3_bind_text(stmt, 1, name, -1, nil)
}

// PLANT-FP(swift-safe-hash, CWE-328): SHA-256 is a strong hash.
func safeHash(data: [UInt8]) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256(data, CC_LONG(data.count), &digest)
    return digest
}

// PLANT-FP(swift-safe-exec, CWE-78): fixed program with a constant argument
// array, no shell involved.
func safeExec() {
    let task = Process()
    task.launchPath = "/bin/ls"
    task.arguments = ["-la"]
    try? task.run()
}
