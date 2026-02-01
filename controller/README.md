# Aegis Controller (Control Plane)

The Controller is the brain of the Aegis Zero Trust network. Written in Go, it serves the web dashboard for user authentication, manages RBAC (Role-Based Access Control), and dispatches allow-rules to Agents via gRPC.

## 🏗️ Architecture

The Controller bridges the user-facing web UI and the backend infrastructure.

![Controller Architecture](./../docs/images/controller_architecture.png)
* **Frontend:** Serves static HTML/JS pages for Login, Dashboard, and User Management.
* **API Layer:** REST API for handling user sessions and database interactions.
* **RPC Client:** Acts as a gRPC client to push authenticated session data to the Edge Agent.

[![](https://mermaid.ink/img/pako:eNqVVgtv6jYU_itWKlY60fJ-ZVWlAts6qdW40HbSytWVk5wEixBzHWctQ_z3Hdt50KCy2yAR-zw-f8c-58Q7y-UeWLZVqexYxKRNdudyCWs4t8m5R8XqvEaM4JkKRp0QYtTsjO4BXXEmRQJo5VB3FQieRJ7yPWuC-in3jWBrKraP8CbHPORCq33fV7qQRVAI6dDpuz0ld8MkliBGq0ArWr12qz04VHDhgXHqdnrQp-f7_b5SWUSBoJsluZ8tIoJPpULmcoukzdQNaRxPwCch3YIgPgtD-6zZaHabbi2Wgq_ATuHS6eUr8-TSbm7eMoFH4yUVgm5t0iXdmqu422cA8EtpiYCP-XrDI4hkulCHNjuDYiFoOgD99wu1cKEUEjeoDOk5KVK73-l3_BzJ9b2B534GibqS5_F3e123kYMNGy71h58BE3giKZbjt3uNIkTfd91B43-wDNpTDKJaVf8XF7Zta4JGcxvgFlarM7WKHl87on4TzKZjMgfxT-qgSBj7yeileu3czL_cMwk4u647N9pFgcc17cRcwNGMY2ZcfEVvz8l4xIljUmjMI6QdhiC-zZJIsjWQl985ycapmkxDGsFX46sejwlwJeMReRwV0mKU4_8RYRr71IVv9zoZX3IB0YIDzI9x1XP3-Dh9wYDVG0NKECUPOQJZX0q5IQ_Jm4rzICkLEIi8LPp3DB-Y54XwSkVOsZD8MLvxn7P5i_o7gPuQiT7uRC5VOOp94JOHNIc4xoXqY85XDM9hCe7q06Hd0chTJ5vGNUpi7ENxTO55wFxSz_TxD4ep2N7ltFP3nLOCjeojV2w38mTwKkU1jBocwWjhQ7A-jaGyWmPo9D4CmY1uxyf90_rQEOn4CGTKQ-ZuyU_YXQXQtdm3k6gT7JsaUg0cToV3BDqXVMbkmcHrp89zQiXNDlONya2LFV4-vhlsuKEgqUNjIH-h8-aAgZcq6vH38DSHEhn8zvz6hoUX0VB1hshkSVy0NnJ5SRaWKtE50vieADazOt2w-s8LC3U3uoqNebb_xkX3uQlD3HyznzbIEz9pxlG3ROOp4iPXSjgZHTDTjUUx-y3kr0aqe4UyVJVpRLn5NHHwcE0nSSPQ9avppMqqzuiLjIJK_jKK4BJ3AbyPgDL9AUba71UFKZEuhpJMJ3dJlm1YSawzrsTK1HexD5q5IfQMgvlbMhbgZVur9rM4wtRuPHua6PmxlSZ3YKUL8Mjq_flOEYhhMqTSI2sdhTH9koDYEl0l78yK6HQBqAsPi4KDj3T5W1Mrd_bau35YO6gmfVGyalYgmGfZ-qZnrUGsqZpaO7XIwtL3w4Vl41BdCxfWItqjz4ZGf3O-ztzwahgsLdunYYyzRCcxJjYWcGGCJQVijHdIadlDjWDZO-vNsi87zcZVu9HoD5qtbs3aomR41Wvhr9Hv9judXmsw3Nesf_V6zavWsDXodxvDbmc4bGsP8BjeKB7MZVffeff_AWI-aRM?type=png)](https://mermaid.live/edit#pako:eNqVVgtv6jYU_itWKlY60fJ-ZVWlAts6qdW40HbSytWVk5wEixBzHWctQ_z3Hdt50KCy2yAR-zw-f8c-58Q7y-UeWLZVqexYxKRNdudyCWs4t8m5R8XqvEaM4JkKRp0QYtTsjO4BXXEmRQJo5VB3FQieRJ7yPWuC-in3jWBrKraP8CbHPORCq33fV7qQRVAI6dDpuz0ld8MkliBGq0ArWr12qz04VHDhgXHqdnrQp-f7_b5SWUSBoJsluZ8tIoJPpULmcoukzdQNaRxPwCch3YIgPgtD-6zZaHabbi2Wgq_ATuHS6eUr8-TSbm7eMoFH4yUVgm5t0iXdmqu422cA8EtpiYCP-XrDI4hkulCHNjuDYiFoOgD99wu1cKEUEjeoDOk5KVK73-l3_BzJ9b2B534GibqS5_F3e123kYMNGy71h58BE3giKZbjt3uNIkTfd91B43-wDNpTDKJaVf8XF7Zta4JGcxvgFlarM7WKHl87on4TzKZjMgfxT-qgSBj7yeileu3czL_cMwk4u647N9pFgcc17cRcwNGMY2ZcfEVvz8l4xIljUmjMI6QdhiC-zZJIsjWQl985ycapmkxDGsFX46sejwlwJeMReRwV0mKU4_8RYRr71IVv9zoZX3IB0YIDzI9x1XP3-Dh9wYDVG0NKECUPOQJZX0q5IQ_Jm4rzICkLEIi8LPp3DB-Y54XwSkVOsZD8MLvxn7P5i_o7gPuQiT7uRC5VOOp94JOHNIc4xoXqY85XDM9hCe7q06Hd0chTJ5vGNUpi7ENxTO55wFxSz_TxD4ep2N7ltFP3nLOCjeojV2w38mTwKkU1jBocwWjhQ7A-jaGyWmPo9D4CmY1uxyf90_rQEOn4CGTKQ-ZuyU_YXQXQtdm3k6gT7JsaUg0cToV3BDqXVMbkmcHrp89zQiXNDlONya2LFV4-vhlsuKEgqUNjIH-h8-aAgZcq6vH38DSHEhn8zvz6hoUX0VB1hshkSVy0NnJ5SRaWKtE50vieADazOt2w-s8LC3U3uoqNebb_xkX3uQlD3HyznzbIEz9pxlG3ROOp4iPXSjgZHTDTjUUx-y3kr0aqe4UyVJVpRLn5NHHwcE0nSSPQ9avppMqqzuiLjIJK_jKK4BJ3AbyPgDL9AUba71UFKZEuhpJMJ3dJlm1YSawzrsTK1HexD5q5IfQMgvlbMhbgZVur9rM4wtRuPHua6PmxlSZ3YKUL8Mjq_flOEYhhMqTSI2sdhTH9koDYEl0l78yK6HQBqAsPi4KDj3T5W1Mrd_bau35YO6gmfVGyalYgmGfZ-qZnrUGsqZpaO7XIwtL3w4Vl41BdCxfWItqjz4ZGf3O-ztzwahgsLdunYYyzRCcxJjYWcGGCJQVijHdIadlDjWDZO-vNsi87zcZVu9HoD5qtbs3aomR41Wvhr9Hv9judXmsw3Nesf_V6zavWsDXodxvDbmc4bGsP8BjeKB7MZVffeff_AWI-aRM)

## Documentation

For detailed information on how to configure and use the Aegis Controller, please refer to the following guides:

* **[Application Guide & Usage](./CONTROLLER_DOCS.md)**: Explains the core concepts (Roles, Services, Users), the administrative setup workflow, and the user dashboard experience.
* **[API Documentation](./API_DOCS.md)**: A complete reference for all API endpoints, including authentication, role management, and service configuration.

## 📋 Prerequisites

* **Go 1.25+**
* **SQLite** (Embedded, no external setup required)

## 🛠️ Build

```bash
cd controller
go mod download
go build -o bin/aegis-controller .

```

## 🏃 Usage

```bash
./bin/aegis-controller [flags]

```

### Configuration

The Controller supports both Environment Variables and Command Line Flags. CLI flags take precedence.

**Core Settings:**

| Env Variable | CLI Flag | Default | Description |
| --- | --- | --- | --- |
| `SERVER_PORT` | `-port` | `:443` | The port the HTTP/gRPC server listens on. |
| `DB_DIR` | N/A | `./data` | Directory to store the SQLite database. |
| `CERT_FILE` | `-cert` | `certs/server.crt` | TLS Certificate path. |
| `KEY_FILE` | `-key` | `certs/server.key` | TLS Private Key path. |

**Agent Connection Settings:**

| Env Variable | Flag | Default | Description |
| --- | --- | --- | --- |
| `JWT_SECRET` | N/A | `DEFAULT_JWT_KEY` | JWT key for signing tokens. |
| `AGENT_ADDRESS` | `-agent-addr` | `172.21.0.10:50001` | Address of the target Aegis Agent. |
| `AGENT_CERT_FILE` | N/A | `certs/controller.pem` | mTLS Cert for talking to Agent. |
| `AGENT_KEY_FILE` | N/A | `certs/controller.key` | mTLS Key for talking to Agent. |

### Running Tests

```bash
# Run all tests with verbose output
JWT_SECRET="test-secret" go test -v ./...

```
