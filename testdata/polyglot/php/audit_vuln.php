<?php
// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.

// PLANT(php-extract, min-profile=standard, CWE-621): variable extraction from user input via extract() (caught by argus/curated)
extract($_GET);

// PLANT(php-dynamic-include, min-profile=max, CWE-98): dynamic include from user input
include($_GET['page']);

// PLANT(php-weak-rand, min-profile=standard, CWE-330): predictable PRNG for a token via rand() (caught by argus/curated)
$token = rand();
echo $token;
