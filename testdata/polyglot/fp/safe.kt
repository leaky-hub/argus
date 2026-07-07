// Safe-code plants for the FP measurement eval (see fp/safe.py header).
// PLANT-FP(id, CWE) marks the correct, non-vulnerable form of a weakness
// class; flagging it is a measured false positive.
import java.security.SecureRandom
import java.sql.Connection

fun safeQuery(conn: Connection, name: String) {
    // PLANT-FP(kt-safe-sql, CWE-89): PreparedStatement with a bound parameter,
    // constant query text.
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
    stmt.setString(1, name)
    val rs = stmt.executeQuery()
    while (rs.next()) {
        println(rs.getString(1))
    }
}

fun safeToken(): String {
    // PLANT-FP(kt-safe-random, CWE-330): SecureRandom is the correct source
    // for security-relevant randomness.
    val bytes = ByteArray(16)
    SecureRandom().nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
}
