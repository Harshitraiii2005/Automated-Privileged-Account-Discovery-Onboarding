# Production-mode Vault (not -dev): integrated raft storage, TLS listener, manual init/unseal.
ui            = true
disable_mlock = true # HashiCorp's recommendation for integrated storage (mlock + mmap'd BoltDB don't mix)
api_addr      = "https://vault:8200"
cluster_addr  = "https://vault:8201"

storage "raft" {
  path    = "/vault/file"
  node_id = "vault-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/vault/tls/vault.crt"
  tls_key_file    = "/vault/tls/vault.key"
  tls_min_version = "tls12"
}
