#pragma once

#include "pch.h"

#include "./batch_file_adapter.h"
#include "../../exception/unsupported_operation_exception.h"
#include <phpcpp.h>
// #include <iostream>

// NewAdapter is the constructor for Adapter.
BatchFileAdapter :: BatchFileAdapter(string file_path): FileAdapter(file_path) {
}

void BatchFileAdapter :: AddPolicies(string sec, string p_type, vector<vector<string>> rules) {
    // Php::out << "can throw" << std::endl;
    throw UnsupportedOperationException("not implemented hello");
}

void BatchFileAdapter :: RemovePolicies(string sec, string p_type, vector<vector<string>> rules) {
    throw UnsupportedOperationException("not implemented");
}