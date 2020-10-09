#include <phpcpp.h>
#include "enforcer.h"

extern "C" {
PHPCPP_EXPORT void *get_module() {
    static Php::Extension ex("phpcpp-casbin", "1.0");

    Php::Namespace casbinNamespace("Casbin");

    Php::Class<Enforcer> enforcer("Enforcer");

    registerEnforcer(enforcer);
    registerManagementApi(enforcer);
    registerRbacApi(enforcer);
    registerCommonApi(enforcer);
    registerRbacApiWithDomains(enforcer);

    casbinNamespace.add(std::move(enforcer));
    ex.add(casbinNamespace);

    return ex;
}
}