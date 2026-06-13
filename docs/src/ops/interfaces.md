# Interfaces & peers

## Interface lifecycle

| Step | UI | CLI |
|------|----|-----|
| Create | `/interfaces/new` | — |
| Edit settings | `/interfaces/{id}/edit` | — |
| Start | `Start` button | — |
| Stop | `Stop` button | — |
| Delete | `Delete` button | — |
| List | `/interfaces` | `wireforge interface list` |

The server generates a Curve25519 keypair through `defguard_wireguard_rs`.
The private key is sealed with the master key before being persisted.

## Peer lifecycle

| Step | UI | CLI |
|------|----|-----|
| Create | `/peers/new` | — |
| Edit | `/peers/{id}/edit` | — |
| Enable / disable | toggle in the row | — |
| Delete | `Delete` button | — |
| Download `.conf` | `/peers/{id}/download` | — |
| QR code | `/peers/{id}/qr` | — |
| List | `/peers` | `wireforge peer list` |

By default, Wireforge allocates the next free IPv4 host inside the interface
CIDR; you can also paste a comma-separated list of allowed IPs manually.
