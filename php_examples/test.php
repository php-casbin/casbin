<?php

use Casbin\Enforcer;

$enforcer = new Enforcer("../examples/basic_model.conf", "../examples/basic_policy.csv");

$resul = $enforcer->Enforce(["alice", "data1", "read"]); // ture
$resul = $enforcer->Enforce(["alice", "data2", "read"]); // false
$resul = $enforcer->Enforce(["bob", "data1", "write"]); // false
$resul = $enforcer->Enforce(["bob", "data2", "write"]); // ture