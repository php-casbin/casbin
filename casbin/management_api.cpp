/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#pragma once

#include "pch.h"

#include "./enforcer.h"
#include <phpcpp.h>

// GetAllSubjects gets the list of subjects that show up in the current policy.
vector<string> Enforcer :: GetAllSubjects() {
    return this->model->GetValuesForFieldInPolicyAllTypes("p", 0);
}
// PHPCPP
Php::Value Enforcer :: getAllSubjects() {
    return this->temp->GetAllSubjects();
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedSubjects(string p_type) {
    return this->model->GetValuesForFieldInPolicy("p", p_type, 0);
}
// PHPCPP
Php::Value Enforcer :: getAllNamedSubjects(Php::Parameters &params) {
    string p_type = params[0];
    return this->temp->GetAllNamedSubjects(p_type);
}

// GetAllObjects gets the list of objects that show up in the current policy.
vector<string> Enforcer :: GetAllObjects() {
    return this->model->GetValuesForFieldInPolicyAllTypes("p", 1);
}
// PHPCPP
Php::Value Enforcer :: getAllObjects() {
    return this->temp->GetAllObjects();
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedObjects(string p_type) {
    return this->model->GetValuesForFieldInPolicy("p", p_type, 1);
}
// PHPCPP
Php::Value Enforcer :: getAllNamedObjects(Php::Parameters &params) {
    string p_type = params[0];
    return this->temp->GetAllNamedObjects(p_type);
}

// GetAllActions gets the list of actions that show up in the current policy.
vector<string> Enforcer :: GetAllActions() {
    return this->model->GetValuesForFieldInPolicyAllTypes("p", 2);
}
// PHPCPP
Php::Value Enforcer :: getAllActions() {
    return this->temp->GetAllActions();
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedActions(string p_type) {
    return this->model->GetValuesForFieldInPolicy("p", p_type, 2);
}
// PHPCPP
Php::Value Enforcer :: getAllNamedActions(Php::Parameters &params) {
    string p_type = params[0];
    return this->temp->GetAllNamedActions(p_type);
}

// GetAllRoles gets the list of roles that show up in the current policy.
vector<string> Enforcer :: GetAllRoles() {
    return this->model->GetValuesForFieldInPolicyAllTypes("g", 1);
}
// PHPCPP
Php::Value Enforcer :: getAllRoles() {
    // return this->temp->model->GetValuesForFieldInPolicyAllTypes("g", 1);
    return this->temp->GetAllRoles();
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedRoles(string p_type) {
    return this->model->GetValuesForFieldInPolicy("g", p_type, 1);
}
// PHPCPP
Php::Value Enforcer :: getAllNamedRoles(Php::Parameters &params) {
    string p_type = params[0];
    return this->temp->GetAllNamedRoles(p_type);
}

// GetPolicy gets all the authorization rules in the policy.
vector<vector<string>> Enforcer :: GetPolicy() {
    return this->GetNamedPolicy("p");
}
// PHPCPP
Php::Value Enforcer :: getPolicy() {
    return this->temp->GetPolicy();
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredPolicy(int field_index, vector<string> field_values) {
    return this->GetFilteredNamedPolicy("p", field_index, field_values);
}
// PHPCPP
Php::Value Enforcer :: getFilteredPolicy(Php::Parameters &params) {
    int field_index = params[0];
    vector<string> field_value = params[1];
    return this->temp->GetFilteredPolicy(field_index, field_value);
}

// GetNamedPolicy gets all the authorization rules in the named policy.
vector<vector<string>> Enforcer :: GetNamedPolicy(string p_type) {
    return this->model->GetPolicy("p", p_type);
}
// PHPCPP
Php::Value Enforcer :: getNamedPolicy(Php::Parameters &params) {
    string p_type = params[0];
    return this->temp->GetNamedPolicy(p_type);
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values) {
    return this->model->GetFilteredPolicy("p", p_type, field_index, field_values);
}
// PHPCPP
Php::Value Enforcer :: getFilteredNamedPolicy(Php::Parameters &params) {
    string p_type = params[0];
    int field_index = params[1];
    vector<string> field_values = params[2];
    return this->temp->GetFilteredNamedPolicy(p_type, field_index, field_values);
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> Enforcer :: GetGroupingPolicy() {
    return this->GetNamedGroupingPolicy("g");
}
// PHPCPP
Php::Value Enforcer :: getGroupingPolicy() {
    return this->temp->GetGroupingPolicy();
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredGroupingPolicy(int field_index, vector<string> field_values) {
    return this->GetFilteredNamedGroupingPolicy("g", field_index, field_values);
}
// PHPCPP
Php::Value Enforcer :: getFilteredGroupingPolicy(Php::Parameters &params) {
    int field_index = params[0];
    vector<string> field_values = params[1];
    return this->temp->GetFilteredGroupingPolicy(field_index, field_values);
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> Enforcer :: GetNamedGroupingPolicy(string p_type) {
    return this->model->GetPolicy("g", p_type);
}
// PHPCPP
Php::Value Enforcer :: getNamedGroupingPolicy(Php::Parameters &params) {
    string p_type = params[0];
    return this->temp->GetNamedGroupingPolicy(p_type);
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    return this->model->GetFilteredPolicy("g", p_type, field_index, field_values);
}
// PHPCPP
Php::Value Enforcer :: getFilteredNamedGroupingPolicy(Php::Parameters &params) {
    string p_type = params[0];
    int field_index = params[1];
    vector<string> field_values = params[2];
    return this->temp->GetFilteredNamedGroupingPolicy(p_type, field_index, field_values);
}

// HasPolicy determines whether an authorization rule exists.
bool Enforcer :: HasPolicy(vector<string> params) {
    return this->HasNamedPolicy("p", params);
}
// PHPCPP
Php::Value Enforcer :: hasPolicy(Php::Parameters &params) {
    vector<string> par = params[0];
    return this->temp->HasPolicy(par);
}

// HasNamedPolicy determines whether a named authorization rule exists.
bool Enforcer :: HasNamedPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->model->HasPolicy("p", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->model->HasPolicy("p", p_type, policy);
}
// PHPCPP
Php::Value Enforcer :: hasNamedPolicy(Php::Parameters &params) {
    string p_type = params[0];
    vector<string> par = params[1];
    return this->temp->HasNamedPolicy(p_type, par);
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddPolicy(vector<string> params) {
    return this->AddNamedPolicy("p", params);
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
bool Enforcer :: AddPolicies(vector<vector<string>> rules) {
    return this->AddNamedPolicies("p", rules);
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddNamedPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->AddPolicy("p", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->AddPolicy("p", p_type, policy);
}
// PHPCPP
Php::Value Enforcer :: addNamedPolicy(Php::Parameters &params) {
    string p_type = params[0];
    vector<string> par = params[1];
    return this->temp->AddNamedPolicy(p_type, par);
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
bool Enforcer :: AddNamedPolicies(string p_type, vector<vector<string>> rules) {
    return this->AddPolicies("p", p_type, rules);
}
// PHPCPP
Php::Value Enforcer :: addNamedPolicies(Php::Parameters &params) {
    string p_type = params[0];
    vector<vector<string>> rules = params[1];
    return this->temp->AddNamedPolicies(p_type, rules);
}

// RemovePolicy removes an authorization rule from the current policy.
bool Enforcer :: RemovePolicy(vector<string> params) {
    return this->RemoveNamedPolicy("p", params);
}

// RemovePolicies removes authorization rules from the current policy.
bool Enforcer :: RemovePolicies(vector<vector<string>> rules) {
    return this->RemoveNamedPolicies("p", rules);
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
bool Enforcer :: RemoveFilteredPolicy(int field_index, vector<string> field_values) {
    return this->RemoveFilteredNamedPolicy("p", field_index, field_values);
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
bool Enforcer :: RemoveNamedPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->RemovePolicy("p", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->RemovePolicy("p", p_type, policy);
}
// PHP
Php::Value Enforcer :: removeNamedPolicy(Php::Parameters &params) {
    string p_type = params[0];
    vector<string> par = params[1];
    return this->temp->RemoveNamedPolicy(p_type, par);
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
bool Enforcer :: RemoveNamedPolicies(string p_type, vector<vector<string>> rules) {
	return this->RemovePolicies("p", p_type, rules);
}
// PHPCPP
Php::Value Enforcer :: removeNamedPolicies(Php::Parameters &params) {
    string p_type = params[0];
    vector<vector<string>> rules = params[1];
	return this->temp->RemoveNamedPolicies(p_type, rules);
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values) {
    return this->RemoveFilteredPolicy("p", p_type, field_index, field_values);
}
// PHPCPP
Php::Value Enforcer :: removeFilteredNamedPolicy(Php::Parameters &params) {
    string p_type = params[0];
    int field_index = params[1];
    vector<string> field_values = params[2];
    return this->RemoveFilteredNamedPolicy(p_type, field_index, field_values);
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
bool Enforcer :: HasGroupingPolicy(vector<string> params) {
    return this->HasNamedGroupingPolicy("g", params);
}
// PHPCPP
Php::Value Enforcer :: hasGroupingPolicy(Php::Parameters &params) {
    vector<string> par = params[0];
    return this->temp->HasGroupingPolicy(par);
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
bool Enforcer :: HasNamedGroupingPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->model->HasPolicy("g", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->model->HasPolicy("g", p_type, policy);
}
// PHPCPP
Php::Value Enforcer :: hasNamedGroupingPolicy(Php::Parameters &params) {
    string p_type = params[0];
    vector<string> par = params[1];
    return this->temp->HasNamedGroupingPolicy(p_type, par);
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddGroupingPolicy(vector<string> params) {
    return this->AddNamedGroupingPolicy("g", params);
}
// PHPCPP
Php::Value Enforcer :: addGroupingPolicy(Php::Parameters &params) {
    vector<string> par = params[0];
    return this->temp->AddGroupingPolicy(par);
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool Enforcer :: AddGroupingPolicies(vector<vector<string>> rules) {
    return this->AddNamedGroupingPolicies("g", rules);
}
// PHPCPP
Php::Value Enforcer :: addGroupingPolicies(Php::Parameters &params) {
    vector<vector<string>> rules = params[0];
    return this->temp->AddGroupingPolicies(rules);
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddNamedGroupingPolicy(string p_type, vector<string> params) {
    bool rule_added;
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        rule_added = this->AddPolicy("g", p_type, str_slice);
    } else {
        vector<string> policy;
        for(int i = 0 ; i < params.size() ; i++)
            policy.push_back(params[i]);

        rule_added = this->AddPolicy("g", p_type, policy);
    }

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_added;
}
// PHPCPP
Php::Value Enforcer :: addNamedGroupingPolicy(Php::Parameters &params) {
    string p_type = params[0];
    vector<string> par = params[1];
    return this->temp->AddNamedGroupingPolicy(p_type, par);
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool Enforcer :: AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules) {
    return this->AddPolicies("g", p_type, rules);
}
// PHPCPP
Php::Value Enforcer :: addNamedGroupingPolicies(Php::Parameters &params) {
    string p_type = params[0];
    vector<vector<string>> rules = params[1];
    return this->temp->AddNamedGroupingPolicies(p_type, rules);
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool Enforcer :: RemoveGroupingPolicy(vector<string> params) {
    return this->RemoveNamedGroupingPolicy("g", params);
}
// PHPCPP
Php::Value Enforcer :: removeGroupingPolicy(Php::Parameters &params) {
    vector<string> par = params[0];
    return this->temp->RemoveGroupingPolicy(par);
}

// RemoveGroupingPolicies removes role inheritance rulea from the current policy.
bool Enforcer :: RemoveGroupingPolicies(vector<vector<string>> rules) {
    return this->RemoveNamedGroupingPolicies("g", rules);
}
// PHPCPP
Php::Value Enforcer :: removeGroupingPolicies(Php::Parameters &params) {
    vector<vector<string>> rules = params[0];
    return this->temp->RemoveGroupingPolicies(rules);
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
bool Enforcer :: RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values) {
    return this->RemoveFilteredNamedGroupingPolicy("g", field_index, field_values);
}
// PHPCPP
Php::Value Enforcer :: removeFilteredGroupingPolicy(Php::Parameters &params) {
    int field_index = params[0];
    vector<string> field_values = params[1];
    return this->temp->RemoveFilteredGroupingPolicy(field_index, field_values);
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
bool Enforcer :: RemoveNamedGroupingPolicy(string p_type, vector<string> params) {
    bool rule_removed;
    if(params.size() == 1){
        vector<string> str_slice{params[0]};
        rule_removed = this->RemovePolicy("g", p_type, str_slice);
    } else {
        vector<string> policy;
        for(int i = 0 ; i < params.size() ; i++)
            policy.push_back(params[i]);

        rule_removed = this->RemovePolicy("g", p_type, policy);
    }

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}
// PHPCPP
Php::Value Enforcer :: removeNamedGroupingPolicy(Php::Parameters &params) {
    string p_type = params[0];
    vector<string> par = params[1];
    return this->temp->RemoveNamedGroupingPolicy(p_type, par);
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
bool Enforcer :: RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules) {
    return this->RemovePolicies("g", p_type, rules);
}
// PHPCPP
Php::Value Enforcer :: removeNamedGroupingPolicies(Php::Parameters &params) {
    string p_type = params[0];
    vector<vector<string>> rules = params[1];
    return this->temp->RemoveNamedGroupingPolicies(p_type, rules);
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    bool rule_removed = this->RemoveFilteredPolicy("g", p_type, field_index, field_values);

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}
// PHPCPP
Php::Value Enforcer :: removeFilteredNamedGroupingPolicy(Php::Parameters &params) {
    string p_type = params[0];
    int field_index = params[1];
    vector<string> field_values = params[2];
    return this->temp->RemoveFilteredNamedGroupingPolicy(p_type, field_index, field_values);
}

// AddFunction adds a customized function.
void Enforcer :: AddFunction(string name, Function function, Index nargs) {
    this->func_map.AddFunction(name, function, nargs);
}
// PHPCPP
// TODO: class Function
// void Enforcer :: addFunction(Php::Parameters &params) {
//     string name = params[0];
//     Function function = params[1];
//     Index nargs = params[2];
//     this->temp->func_map.AddFunction(name, function, nargs);
// }

void registerManagementApi(Php::Class<Enforcer> &enforcer)
{
    enforcer.method<&Enforcer::getAllSubjects>("getAllSubjects");
    enforcer.method<&Enforcer::getAllNamedSubjects>("getAllNamedSubjects");
    enforcer.method<&Enforcer::getAllObjects>("getAllObjects");
    enforcer.method<&Enforcer::getAllNamedObjects>("getAllNamedObjects");
    enforcer.method<&Enforcer::getAllActions>("getAllActions");
    enforcer.method<&Enforcer::getAllNamedActions>("getAllNamedActions");
    enforcer.method<&Enforcer::getAllRoles>("getAllRoles");
    enforcer.method<&Enforcer::getAllNamedRoles>("getAllNamedRoles");
    enforcer.method<&Enforcer::getPolicy>("getPolicy");
    enforcer.method<&Enforcer::getFilteredPolicy>("getFilteredPolicy");
    enforcer.method<&Enforcer::getNamedPolicy>("getNamedPolicy");
    enforcer.method<&Enforcer::getFilteredNamedPolicy>("getFilteredNamedPolicy");
    enforcer.method<&Enforcer::getGroupingPolicy>("getGroupingPolicy");
    enforcer.method<&Enforcer::getFilteredGroupingPolicy>("getFilteredGroupingPolicy");
    enforcer.method<&Enforcer::getNamedGroupingPolicy>("getNamedGroupingPolicy");
    enforcer.method<&Enforcer::getFilteredNamedGroupingPolicy>("getFilteredNamedGroupingPolicy");
    enforcer.method<&Enforcer::hasPolicy>("hasPolicy");
    enforcer.method<&Enforcer::hasNamedPolicy>("hasNamedPolicy");
    enforcer.method<&Enforcer::addNamedPolicy>("addNamedPolicy");
    enforcer.method<&Enforcer::addNamedPolicies>("addNamedPolicies");
    enforcer.method<&Enforcer::removeNamedPolicy>("removeNamedPolicy");
    enforcer.method<&Enforcer::removeNamedPolicies>("removeNamedPolicies");
    enforcer.method<&Enforcer::removeFilteredNamedPolicy>("removeFilteredNamedPolicy");
    enforcer.method<&Enforcer::hasGroupingPolicy>("hasGroupingPolicy");
    enforcer.method<&Enforcer::hasNamedGroupingPolicy>("hasNamedGroupingPolicy");
    enforcer.method<&Enforcer::addGroupingPolicy>("addGroupingPolicy");
    enforcer.method<&Enforcer::addGroupingPolicies>("addGroupingPolicies");
    enforcer.method<&Enforcer::addNamedGroupingPolicy>("addNamedGroupingPolicy");
    enforcer.method<&Enforcer::addNamedGroupingPolicies>("addNamedGroupingPolicies");
    enforcer.method<&Enforcer::removeGroupingPolicy>("removeGroupingPolicy");
    enforcer.method<&Enforcer::removeGroupingPolicies>("removeGroupingPolicies");
    enforcer.method<&Enforcer::removeNamedGroupingPolicy>("removeNamedGroupingPolicy");
    enforcer.method<&Enforcer::removeNamedGroupingPolicies>("removeNamedGroupingPolicies");
    enforcer.method<&Enforcer::removeFilteredNamedGroupingPolicy>("removeFilteredNamedGroupingPolicy");
    // enforcer.method<&Enforcer::addFunction>("addFunction");
}