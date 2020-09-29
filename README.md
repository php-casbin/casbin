<h1 align="center">
    Casbin
</h1>

<p align="center">
    <strong>Casbin is used to build Casbin-cpp into a PHP dynamic library via PHP-CPP.</strong>
</p>

## Installation

This application needs to be compiled, and also relies on the PHP-CPP library, so you will need requirements:
* [PHP-CPP](https://github.com/CopernicaMarketingSoftware/PHP-CPP)
* PHP >= 7.0
* GCC
* make

### Install extension

```shell
$ git clone https://github.com/php-casbin/casbin.git
$ cd casbin
$ make
$ make library
$ sudo make install
```

To get rid of intermediate files generated during building of library:
```shell
$ make clean
```

## Usage

### Get started

New a Casbin enforcer with a model file and a policy file:

```php
use Casbin\Enforcer;

$e = new Enforcer("path/to/model.conf", "path/to/policy.csv");
```

Add an enforcement hook into your code right before the access happens:

```php
$params = [
    "alice", // the user that wants to access a resource.
    "data1", // the resource that is going to be accessed.
    "read" // the operation that the user performs on the resource.
]

if ($e->enforce($params) === true) {
    // permit alice to read data1
} else {
    // deny the request, show an error
}
```

### Using Enforcer Api

It provides a very rich api to facilitate various operations on the Policy:

Gets all roles:

```php
$e->getAllRoles();
```

Gets all the authorization rules in the policy.:

```php
$e->getPolicy();
```

Gets the roles that a user has.

```php
$e->getRolesForUser('eve');
```

Gets the users that has a role.

```php
$e->getUsersForRole('writer');
```

Determines whether a user has a role.

```php
$e->hasRoleForUser('eve', 'writer');
```

Adds a role for a user.

```php
$e->addRoleForUser('eve', 'writer');
```

Adds a permission for a user or role.

```php
// to user
$e->addPermissionForUser('eve', ['articles', 'read']);
// to role
$e->addPermissionForUser('writer', ['articles','edit']);
```

Deletes a role for a user.

```php
$e->deleteRoleForUser('eve', 'writer');
```

Deletes all roles for a user.

```php
$e->deleteRolesForUser('eve');
```

Deletes a role.

```php
$e->deleteRole('writer');
```

Deletes a permission.

```php
$e->deletePermission(['articles', 'read']);
```

Deletes a permission for a user or role.

```php
$e->deletePermissionForUser('eve', ['articles', 'read']);
```

Deletes permissions for a user or role.

```php
// to user
$e->deletePermissionsForUser('eve');
// to role
$e->deletePermissionsForUser('writer');
```

Gets permissions for a user or role.

```php
$e->getPermissionsForUser('eve');
```

Determines whether a user has a permission.

```php
$e->hasPermissionForUser('eve', ['articles', 'read']);
```

See [Casbin API](https://casbin.org/docs/en/management-api) for more APIs.

## Thinks

[Casbin](https://github.com/php-casbin/php-casbin) in Laravel. You can find the full documentation of Casbin [on the website](https://casbin.org/).

## License

This project is licensed under the [Apache 2.0 license](LICENSE).