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

#ifndef CASBIN_CPP_ENFORCER
#define CASBIN_CPP_ENFORCER

#include<memory>
#include "./rbac/role_manager.h"
#include "./model/function.h"
#include "./enforcer_interface.h"
#include "./persist/filtered_adapter.h"

#include <phpcpp.h>

// Enforcer is the main interface for authorization enforcement and policy management.
class Enforcer : public Php::Base, public IEnforcer{
    private:

        string model_path;
        shared_ptr<Model> model;
        FunctionMap func_map;
        shared_ptr<Effector> eft;

        shared_ptr<Adapter> adapter;
        shared_ptr<Watcher> watcher;

        bool enabled;
        bool auto_save;
        bool auto_build_role_links;
        bool auto_notify_watcher;

        // enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool enforce(string matcher, Scope scope);

    public:

        shared_ptr<RoleManager> rm;

        /**
         * Enforcer is the default constructor.
         */
        Enforcer();
        /**
         * Enforcer initializes an enforcer with a model file and a policy file.
         *
         * @param model_path the path of the model file.
         * @param policy_file the path of the policy file.
         */
        Enforcer(string model_path, string policy_file);
        /**
         * Enforcer initializes an enforcer with a database adapter.
         *
         * @param model_path the path of the model file.
         * @param adapter the adapter.
         */
        Enforcer(string model_path, shared_ptr<Adapter> adapter);
        /**
         * Enforcer initializes an enforcer with a model and a database adapter.
         *
         * @param m the model.
         * @param adapter the adapter.
         */
        Enforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter);
        /**
         * Enforcer initializes an enforcer with a model.
         *
         * @param m the model.
         */
        Enforcer(shared_ptr<Model> m);
        /**
         * Enforcer initializes an enforcer with a model file.
         *
         * @param model_path the path of the model file.
         */
        Enforcer(string model_path);
        /**
         * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
         *
         * @param model_path the path of the model file.
         * @param policy_file the path of the policy file.
         * @param enable_log whether to enable Casbin's log.
         */
        Enforcer(string model_path, string policy_file, bool enable_log);

        // PHPCPP
        Enforcer *temp;

        // PHPCPP
        void __construct(Php::Parameters &params);

        // InitWithFile initializes an enforcer with a model file and a policy file.
        void InitWithFile(string model_path, string policy_path);
        // InitWithAdapter initializes an enforcer with a database adapter.
        void InitWithAdapter(string model_path, shared_ptr<Adapter> adapter);
        // InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
        void InitWithModelAndAdapter(shared_ptr<Model> m, shared_ptr<Adapter> adapter);
        void Initialize();
        // LoadModel reloads the model from the model CONF file.
        // Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        void LoadModel();
        // GetModel gets the current model.
        shared_ptr<Model> GetModel();
        // SetModel sets the current model.
        void SetModel(shared_ptr<Model> m);
        // GetAdapter gets the current adapter.
        shared_ptr<Adapter> GetAdapter();
        // SetAdapter sets the current adapter.
        void SetAdapter(shared_ptr<Adapter> adapter);
        // SetWatcher sets the current watcher.
        void SetWatcher(shared_ptr<Watcher> watcher);
        // GetRoleManager gets the current role manager.
        shared_ptr<RoleManager> GetRoleManager();
        // SetRoleManager sets the current role manager.
        void SetRoleManager(shared_ptr <RoleManager> rm);
        // SetEffector sets the current effector.
        void SetEffector(shared_ptr<Effector> eft);
        // ClearPolicy clears all policy.
        void ClearPolicy();
        // LoadPolicy reloads the policy from file/database.
        void LoadPolicy();
        //LoadFilteredPolicy reloads a filtered policy from file/database.
        template<typename Filter>
        void LoadFilteredPolicy(Filter filter);
        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();
        // SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
        void SavePolicy();
        // EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
        void EnableEnforce(bool enable);
        // EnableLog changes whether Casbin will log messages to the Logger.
        // void EnableLog(bool enable) {
            // log.GetLogger().EnableLog(enable);
        // }

        // EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
        void EnableAutoNotifyWatcher(bool enable);
        // EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
        void EnableAutoSave(bool auto_save);
        // EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
        void EnableAutoBuildRoleLinks(bool auto_build_role_links);
        // BuildRoleLinks manually rebuild the role inheritance relations.
        void BuildRoleLinks();
        // BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
        void BuildIncrementalRoleLinks(policy_op op, string p_type, vector<vector<string>> rules);
        // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(Scope scope);
        // Enforce with a vector param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(vector<string> params);
        // Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(unordered_map<string,string> params);

        // PHPCPP
        Php::Value Enforce(Php::Parameters &params);

        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, Scope scope);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, vector<string> params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, unordered_map<string, string> params);

        /*Management API member functions.*/
        vector<string> GetAllSubjects();
        Php::Value getAllSubjects();
        vector<string> GetAllNamedSubjects(string p_type);
        Php::Value getAllNamedSubjects(Php::Parameters &parames);
        vector<string> GetAllObjects();
        Php::Value getAllObjects();
        vector<string> GetAllNamedObjects(string p_type);
        Php::Value getAllNamedObjects(Php::Parameters &params);
        vector<string> GetAllActions();
        Php::Value getAllActions();
        vector<string> GetAllNamedActions(string p_type);
        Php::Value getAllNamedActions(Php::Parameters &params);
        vector<string> GetAllRoles();
        Php::Value getAllRoles();
        vector<string> GetAllNamedRoles(string p_type);
        Php::Value getAllNamedRoles(Php::Parameters &params);
        vector<vector<string>> GetPolicy();
        Php::Value getPolicy();
        vector<vector<string>> GetFilteredPolicy(int field_index, vector<string> field_values);
        Php::Value getFilteredPolicy(Php::Parameters &params);
        vector<vector<string>> GetNamedPolicy(string p_type);
        Php::Value getNamedPolicy(Php::Parameters &params);
        vector<vector<string>> GetFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values);
        Php::Value getFilteredNamedPolicy(Php::Parameters &params);
        vector<vector<string>> GetGroupingPolicy();
        Php::Value getGroupingPolicy();
        vector<vector<string>> GetFilteredGroupingPolicy(int field_index, vector<string> field_values);
        Php::Value getFilteredGroupingPolicy(Php::Parameters &params);
        vector<vector<string>> GetNamedGroupingPolicy(string p_type);
        Php::Value getNamedGroupingPolicy(Php::Parameters &params);
        vector<vector<string>> GetFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values);
        Php::Value getFilteredNamedGroupingPolicy(Php::Parameters &params);
        bool HasPolicy(vector<string> params);
        Php::Value hasPolicy(Php::Parameters &params);
        bool HasNamedPolicy(string p_type, vector<string> params);
        Php::Value hasNamedPolicy(Php::Parameters &params);
        bool AddPolicy(vector<string> params);
        Php::Value addPolicy(Php::Parameters &params);
        bool AddPolicies(vector<vector<string>> rules);
        Php::Value addPolicies(Php::Parameters &params);
        bool AddNamedPolicy(string p_type, vector<string> params);
        Php::Value addNamedPolicy(Php::Parameters &params);
        bool AddNamedPolicies(string p_type, vector<vector<string>> rules);
        Php::Value addNamedPolicies(Php::Parameters &params);
        bool RemovePolicy(vector<string> params);
        Php::Value removePolicy(Php::Parameters &params);
        bool RemovePolicies(vector<vector<string>> rules);
        Php::Value removePolicies(Php::Parameters &params);
        bool RemoveFilteredPolicy(int field_index, vector<string> field_values);
        Php::Value removeFilteredPolicy(Php::Parameters &params);
        bool RemoveNamedPolicy(string p_type, vector<string> params);
        Php::Value removeNamedPolicy(Php::Parameters &params);
        bool RemoveNamedPolicies(string p_type, vector<vector<string>> rules);
        Php::Value removeNamedPolicies(Php::Parameters &params);
        bool RemoveFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values);
        Php::Value removeFilteredNamedPolicy(Php::Parameters &params);
        bool HasGroupingPolicy(vector<string> params);
        Php::Value hasGroupingPolicy(Php::Parameters &params);
        bool HasNamedGroupingPolicy(string p_type, vector<string> params);
        Php::Value hasNamedGroupingPolicy(Php::Parameters &params);
        bool AddGroupingPolicy(vector<string> params);
        Php::Value addGroupingPolicy(Php::Parameters &params);
        bool AddGroupingPolicies(vector<vector<string>> rules);
        Php::Value addGroupingPolicies(Php::Parameters &params);
        bool AddNamedGroupingPolicy(string p_type, vector<string> params);
        Php::Value addNamedGroupingPolicy(Php::Parameters &params);
        bool AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules);
        Php::Value addNamedGroupingPolicies(Php::Parameters &params);
        bool RemoveGroupingPolicy(vector<string> params);
        Php::Value removeGroupingPolicy(Php::Parameters &params);
        bool RemoveGroupingPolicies(vector<vector<string>> rules);
        Php::Value removeGroupingPolicies(Php::Parameters &params);
        bool RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values);
        Php::Value removeFilteredGroupingPolicy(Php::Parameters &params);
        bool RemoveNamedGroupingPolicy(string p_type, vector<string> params);
        Php::Value removeNamedGroupingPolicy(Php::Parameters &params);
        bool RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules);
        Php::Value removeNamedGroupingPolicies(Php::Parameters &params);
        bool RemoveFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values);
        Php::Value removeFilteredNamedGroupingPolicy(Php::Parameters &params);
        void AddFunction(string name, Function function, Index nargs);
        void addFunction(Php::Parameters &params);

        /*RBAC API member functions.*/
        vector<string> GetRolesForUser(string name, vector<string> domain = {});
        Php::Value getRolesForUser(Php::Parameters &params);
        vector<string> GetUsersForRole(string name, vector<string> domain = {});
        Php::Value getUsersForRole(Php::Parameters &params);
        bool HasRoleForUser(string name, string role);
        Php::Value hasRoleForUser(Php::Parameters &params);
        bool AddRoleForUser(string user, string role);
        Php::Value addRoleForUser(Php::Parameters &params);
        bool AddRolesForUser(string user, vector<string> roles);
        Php::Value addRolesForUser(Php::Parameters &params);
        bool AddPermissionForUser(string user, vector<string> permission);
        Php::Value addPermissionForUser(Php::Parameters &params);
        bool DeletePermissionForUser(string user, vector<string> permission);
        Php::Value deletePermissionForUser(Php::Parameters &params);
        bool DeletePermissionsForUser(string user);
        Php::Value deletePermissionsForUser(Php::Parameters &params);
        vector<vector<string>> GetPermissionsForUser(string user);
        Php::Value getPermissionsForUser(Php::Parameters &params);
        bool HasPermissionForUser(string user, vector<string> permission);
        Php::Value hasPermissionForUser(Php::Parameters &params);
        vector<string> GetImplicitRolesForUser(string name, vector<string> domain = {});
        Php::Value getImplicitRolesForUser(Php::Parameters &params);
        vector<vector<string>> GetImplicitPermissionsForUser(string user, vector<string> domain = {});
        Php::Value getImplicitPermissionsForUser(Php::Parameters &params);
        vector<string> GetImplicitUsersForPermission(vector<string> permission);
        Php::Value getImplicitUsersForPermission(Php::Parameters &params);
        bool DeleteRoleForUser(string user, string role);
        Php::Value deleteRoleForUser(Php::Parameters &params);
        bool DeleteRolesForUser(string user);
        Php::Value deleteRolesForUser(Php::Parameters &params);
        bool DeleteUser(string user);
        Php::Value deleteUser(Php::Parameters &params);
        bool DeleteRole(string role);
        Php::Value deleteRole(Php::Parameters &params);
        bool DeletePermission(vector<string> permission);
        Php::Value deletePermission(Php::Parameters &params);

        /* Internal API member functions */
        bool AddPolicy(string sec, string p_type, vector<string> rule);
        bool AddPolicies(string sec, string p_type, vector<vector<string>> rules);
        bool RemovePolicy(string sec , string p_type , vector<string> rule);
        bool RemovePolicies(string sec, string p_type, vector<vector<string>> rules);
        bool RemoveFilteredPolicy(string sec , string p_type , int field_index , vector<string> field_values);

        /* RBAC API with domains.*/
        vector<string> GetUsersForRoleInDomain(string name, string domain = {});
        Php::Value getUsersForRoleInDomain(Php::Parameters &params);
        vector<string> GetRolesForUserInDomain(string name, string domain = {});
        Php::Value getRolesForUserInDomain(Php::Parameters &params);
        vector<vector<string>> GetPermissionsForUserInDomain(string user, string domain = {});
        Php::Value getPermissionsForUserInDomain(Php::Parameters &params);
        bool AddRoleForUserInDomain(string user, string role, string domain = {});
        Php::Value addRoleForUserInDomain(Php::Parameters &params);
        bool DeleteRoleForUserInDomain(string user, string role, string domain = {});
        Php::Value deleteRoleForUserInDomain(Php::Parameters &params);

};

// void registerEnforcer(Php::Namespace &casbinNamespace);
void registerEnforcer(Php::Class<Enforcer> &enforcer);
void registerManagementApi(Php::Class<Enforcer> &enforcer);
void registerRbacApi(Php::Class<Enforcer> &enforcer);
void registerCommonApi(Php::Class<Enforcer> &enforcer);
void registerRbacApiWithDomains(Php::Class<Enforcer> &enforcer);

#endif