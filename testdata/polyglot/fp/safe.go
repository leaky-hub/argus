// Safe-code plants for the FP measurement eval (see fp/safe.py header).
// PLANT-FP(id, CWE) marks the correct, non-vulnerable form of a weakness
// class; flagging it is a measured false positive. Never compiled (testdata
// is invisible to the go tool); exists only to be scanned.
package fp

import "os/exec"

func safeExec() ([]byte, error) {
	// PLANT-FP(go-safe-exec, CWE-78): fixed program with a constant argument
	// vector, no shell involved.
	return exec.Command("ls", "-la").Output()
}
