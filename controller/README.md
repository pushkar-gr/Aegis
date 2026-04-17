# Aegis Controller (Control Plane)

The Controller is the brain of the Aegis Zero Trust network. Written in Go, it serves the web dashboard for user authentication, manages RBAC, and dispatches allow-rules to Agents via gRPC.

## Architecture

The Controller bridges the user facing web UI and the backend infrastructure.

* **Frontend:** Serves static HTML/JS pages for Login, Dashboard, and User Management.
* **API Layer:** REST API for handling user sessions and database interactions.
* **RPC Client:** Acts as a gRPC client to push authenticated session data to the Edge Agent.

[![](https://mermaid.ink/img/pako:eNqVVgtv6jYU_itWKlY60fJ-ZVWlAts6qdW40HbSytWVk5wEixBzHWctQ_z3Hdt50KCy2yAR-zw-f8c-58Q7y-UeWLZVqexYxKRNdudyCWs4t8m5R8XqvEaM4JkKRp0QYtTsjO4BXXEmRQJo5VB3FQieRJ7yPWuC-in3jWBrKraP8CbHPORCq33fV7qQRVAI6dDpuz0ld8MkliBGq0ArWr12qz04VHDhgXHqdnrQp-f7_b5SWUSBoJsluZ8tIoJPpULmcoukzdQNaRxPwCch3YIgPgtD-6zZaHabbi2Wgq_ATuHS6eUr8-TSbm7eMoFH4yUVgm5t0iXdmqu422cA8EtpiYCP-XrDI4hkulCHNjuDYiFoOgD99wu1cKEUEjeoDOk5KVK73-l3_BzJ9b2B534GibqS5_F3e123kYMNGy71h58BE3giKZbjt3uNIkTfd91B43-wDNpTDKJaVf8XF7Zta4JGcxvgFlarM7WKHl87on4TzKZjMgfxT-qgSBj7yeileu3czL_cMwk4u647N9pFgcc17cRcwNGMY2ZcfEVvz8l4xIljUmjMI6QdhiC-zZJIsjWQl985ycapmkxDGsFX46sejwlwJeMReRwV0mKU4_8RYRr71IVv9zoZX3IB0YIDzI9x1XP3-Dh9wYDVG0NKECUPOQJZX0q5IQ_Jm4rzICkLEIi8LPp3DB-Y54XwSkVOsZD8MLvxn7P5i_o7gPuQiT7uRC5VOOp94JOHNIc4xoXqY85XDM9hCe7q06Hd0chTJ5vGNUpi7ENxTO55wFxSz_TxD4ep2N7ltFP3nLOCjeojV2w38mTwKkU1jBocwWjhQ7A-jaGyWmPo9D4CmY1uxyf90_rQEOn4CGTKQ-ZuyU_YXQXQtdm3k6gT7JsaUg0cToV3BDqXVMbkmcHrp89zQiXNDlONya2LFV4-vhlsuKEgqUNjIH-h8-aAgZcq6vH38DSHEhn8zvz6hoUX0VB1hshkSVy0NnJ5SRaWKtE50vieADazOt2w-s8LC3U3uoqNebb_xkX3uQlD3HyznzbIEz9pxlG3ROOp4iPXSjgZHTDTjUUx-y3kr0aqe4UyVJVpRLn5NHHwcE0nSSPQ9avppMqqzuiLjIJK_jKK4BJ3AbyPgDL9AUba71UFKZEuhpJMJ3dJlm1YSawzrsTK1HexD5q5IfQMgvlbMhbgZVur9rM4wtRuPHua6PmxlSZ3YKUL8Mjq_flOEYhhMqTSI2sdhTH9koDYEl0l78yK6HQBqAsPi4KDj3T5W1Mrd_bau35YO6gmfVGyalYgmGfZ-qZnrUGsqZpaO7XIwtL3w4Vl41BdCxfWItqjz4ZGf3O-ztzwahgsLdunYYyzRCcxJjYWcGGCJQVijHdIadlDjWDZO-vNsi87zcZVu9HoD5qtbs3aomR41Wvhr9Hv9judXmsw3Nesf_V6zavWsDXodxvDbmc4bGsP8BjeKB7MZVffeff_AWI-aRM?type=png)](https://mermaid.live/edit#pako:eNqVVgtv6jYU_itWKlY60fJ-ZVWlAts6qdW40HbSytWVk5wEixBzHWctQ_z3Hdt50KCy2yAR-zw-f8c-58Q7y-UeWLZVqexYxKRNdudyCWs4t8m5R8XqvEaM4JkKRp0QYtTsjO4BXXEmRQJo5VB3FQieRJ7yPWuC-in3jWBrKraP8CbHPORCq33fV7qQRVAI6dDpuz0ld8MkliBGq0ArWr12qz04VHDhgXHqdnrQp-f7_b5SWUSBoJsluZ8tIoJPpULmcoukzdQNaRxPwCch3YIgPgtD-6zZaHabbi2Wgq_ATuHS6eUr8-TSbm7eMoFH4yUVgm5t0iXdmqu422cA8EtpiYCP-XrDI4hkulCHNjuDYiFoOgD99wu1cKEUEjeoDOk5KVK73-l3_BzJ9b2B534GibqS5_F3e123kYMNGy71h58BE3giKZbjt3uNIkTfd91B43-wDNpTDKJaVf8XF7Zta4JGcxvgFlarM7WKHl87on4TzKZjMgfxT-qgSBj7yeileu3czL_cMwk4u647N9pFgcc17cRcwNGMY2ZcfEVvz8l4xIljUmjMI6QdhiC-zZJIsjWQl985ycapmkxDGsFX46sejwlwJeMReRwV0mKU4_8RYRr71IVv9zoZX3IB0YIDzI9x1XP3-Dh9wYDVG0NKECUPOQJZX0q5IQ_Jm4rzICkLEIi8LPp3DB-Y54XwSkVOsZD8MLvxn7P5i_o7gPuQiT7uRC5VOOp94JOHNIc4xoXqY85XDM9hCe7q06Hd0chTJ5vGNUpi7ENxTO55wFxSz_TxD4ep2N7ltFP3nLOCjeojV2w38mTwKkU1jBocwWjhQ7A-jaGyWmPo9D4CmY1uxyf90_rQEOn4CGTKQ-ZuyU_YXQXQtdm3k6gT7JsaUg0cToV3BDqXVMbkmcHrp89zQiXNDlONya2LFV4-vhlsuKEgqUNjIH-h8-aAgZcq6vH38DSHEhn8zvz6hoUX0VB1hshkSVy0NnJ5SRaWKtE50vieADazOt2w-s8LC3U3uoqNebb_xkX3uQlD3HyznzbIEz9pxlG3ROOp4iPXSjgZHTDTjUUx-y3kr0aqe4UyVJVpRLn5NHHwcE0nSSPQ9avppMqqzuiLjIJK_jKK4BJ3AbyPgDL9AUba71UFKZEuhpJMJ3dJlm1YSawzrsTK1HexD5q5IfQMgvlbMhbgZVur9rM4wtRuPHua6PmxlSZ3YKUL8Mjq_flOEYhhMqTSI2sdhTH9koDYEl0l78yK6HQBqAsPi4KDj3T5W1Mrd_bau35YO6gmfVGyalYgmGfZ-qZnrUGsqZpaO7XIwtL3w4Vl41BdCxfWItqjz4ZGf3O-ztzwahgsLdunYYyzRCcxJjYWcGGCJQVijHdIadlDjWDZO-vNsi87zcZVu9HoD5qtbs3aomR41Wvhr9Hv9judXmsw3Nesf_V6zavWsDXodxvDbmc4bGsP8BjeKB7MZVffeff_AWI-aRM)

## Documentation

For detailed information on how to configure and use the Aegis Controller:

* **[Application Guide & Usage](./CONTROLLER_DOCS.md)**: Explains the core concepts (Roles, Services, Users), the administrative setup workflow, and the user dashboard experience.
* **[API Documentation](./API_DOCS.md)**: A complete reference for all API endpoints, including authentication, role management, and service configuration.

## Prerequisites

* **Go 1.25+**
* **SQLite** (Embedded, no external setup required)

## Build

```bash
cd controller
go mod download
go build -o bin/aegis-controller .
```

## Usage

```bash
./bin/aegis-controller
```

### Configuration

All settings are loaded from a TOML configuration file (default: `config.toml` in the working directory). Copy `config.toml` from the repository root, adjust the values, and place it next to the binary.

> **Override**: The `JWT_SECRET` environment variable, if set, always overrides `auth.jwt_secret` in the file. This is convenient for container deployments.

#### `[database]`

| Key | Default | Description |
| --- | --- | --- |
| `dir` | `./data` | Directory for the SQLite database file. |
| `max_open_conns` | `1` | Maximum number of open DB connections. |
| `max_idle_conns` | `1` | Maximum number of idle connections in the pool. |
| `conn_max_lifetime` | `1h` | Maximum time a DB connection may be reused (Go duration string). |

#### `[server]`

| Key | Default | Description |
| --- | --- | --- |
| `port` | `:443` | TCP address the HTTPS server listens on (e.g. `:8443`). |
| `cert_file` | `certs/server.crt` | Path to the TLS certificate. |
| `key_file` | `certs/server.key` | Path to the TLS private key. |

#### `[agent]`

| Key | Default | Description |
| --- | --- | --- |
| `address` | `172.21.0.10:50001` | `host:port` of the Aegis Agent's gRPC listener. |
| `cert_file` | `certs/controller.pem` | mTLS client certificate sent to the Agent. |
| `key_file` | `certs/controller.key` | mTLS client private key. |
| `ca_file` | `certs/ca.pem` | CA certificate used to verify the Agent's identity. |
| `server_name` | `aegis-agent` | Expected TLS SNI name of the Agent. |
| `call_timeout` | `1s` | Timeout for individual gRPC calls to the Agent. |

#### `[monitor]`

| Key | Default | Description |
| --- | --- | --- |
| `retry_delay` | `5s` | How long to wait before retrying a failed Agent health-check. |
| `ip_update_interval` | `60s` | How often to push user-IP updates to the Agent. |

#### `[auth]`

| Key | Default | Description |
| --- | --- | --- |
| `jwt_secret` | `CHANGE_ME` | Secret used to sign JWT access tokens. **Must be changed.** |
| `jwt_token_lifetime` | `60s` | Access token lifetime (Go duration string). |
| `jwt_private_key` | `keys/jwt_private.pem` | RSA/EC private key for asymmetric JWT signing (optional). |
| `jwt_public_key` | `keys/jwt_public.pem` | Corresponding public key (optional). |

#### `[oidc]`

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable OpenID Connect / OAuth2 SSO. |
| `google_client_id` | `""` | Google OAuth2 client ID. |
| `google_secret` | `""` | Google OAuth2 client secret. |
| `github_client_id` | `""` | GitHub OAuth2 client ID. |
| `github_secret` | `""` | GitHub OAuth2 client secret. |
| `redirect_url` | `https://localhost/api/auth/oidc/callback` | OAuth2 redirect URI registered with the provider. |
| `role_mapping_rules` | `{"domain_mappings":{...}}` | JSON rules that map OIDC attributes to local roles. |

### Running Tests

```bash
JWT_SECRET="test-secret" go test -v ./...
```
