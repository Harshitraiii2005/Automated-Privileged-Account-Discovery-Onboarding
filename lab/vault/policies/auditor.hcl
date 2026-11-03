# Compliance reviewer: configuration, metadata and rotation state. No credential is readable.
path "sys/audit" {
  capabilities = ["read", "sudo"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/auth" {
  capabilities = ["read"]
}

path "sys/policies/acl" {
  capabilities = ["list"]
}

path "sys/policies/acl/*" {
  capabilities = ["read", "list"]
}

path "sys/policies/password/+" {
  capabilities = ["read"]
}

path "auth/ldap/groups" {
  capabilities = ["list"]
}

path "auth/ldap/groups/*" {
  capabilities = ["read", "list"]
}

path "ldap/config" {
  capabilities = ["read"]
}

path "ldap/static-role/*" {
  capabilities = ["read", "list"]
}

path "safes/metadata/*" {
  capabilities = ["read", "list"]
}
