<?php

use Casbin\Enforcer;

$enforcer = new Enforcer("../examples/basic_model.conf", "../examples/basic_policy.csv");

$result1 = $enforcer->Enforce(["alice", "data1", "read"]); // ture
if ($result1 !== true) echo "result1 is error " . PHP_EOL;
$result2 = $enforcer->Enforce(["alice", "data2", "read"]); // false
if ($result2 !== false) echo "result2 is error" . PHP_EOL;
$result3 = $enforcer->Enforce(["bob", "data1", "write"]); // false
if ($result3 !== false) echo "result3 is error" . PHP_EOL;
$result4 = $enforcer->Enforce(["bob", "data2", "write"]); // ture
if ($result4 !== true) echo "result4 is error" . PHP_EOL;
