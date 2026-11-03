# AutoOnboard onboarder: creates safes (ACL policies + LDAP group mappings), LDAP static roles and
# safe metadata. It can never read or set a credential: Vault rotates LDAP passwords itself on
# import, and the CPM sets Linux passwords.
path "sys/policies/acl/safe-*" {
  capabilities = ["create", "read", "update"]
}

# Safe membership = directory group -> safe policies. Only safe-* policies may be granted.
path "auth/ldap/groups/*" {
  capabilities       = ["create", "read", "update"]
  allowed_parameters = { "policies" = ["safe-*"] }
}

path "ldap/static-role/*" {
  capabilities = ["create", "read", "update", "list"]
}

path "safes/metadata/*" {
  capabilities = ["create", "read", "update", "list"]
}
