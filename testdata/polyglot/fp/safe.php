<?php
// Safe-code plants for the FP measurement eval (see fp/safe.py header).
// PLANT-FP(id, CWE) marks the correct, non-vulnerable form of a weakness
// class; flagging it is a measured false positive.

// PLANT-FP(php-safe-random, CWE-330): random_int is a CSPRNG, the correct
// source for security-relevant randomness.
$token = bin2hex(random_bytes(16));
$pick = random_int(0, 100);
echo $token, $pick;
