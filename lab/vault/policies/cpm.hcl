# AutoOnboard CPM: verifies, rotates and reconciles credentials of onboarded accounts. It cannot
# create safes, change policies or touch auth configuration.
path "safes/data/*" {
  capabilities = ["create", "read", "update"]
}

path "safes/metadata/*" {
  capabilities = ["read", "list"]
}

path "ldap/static-role/*" {
  capabilities = ["read", "list"]
}

path "ldap/static-cred/*" {
  capabilities = ["read"]
}

path "ldap/rotate-role/*" {
  capabilities = ["update"]
}

path "sys/policies/password/autoonboard-unix/generate" {
  capabilities = ["read"]
}
