-- Allow Wireforge to act as a Linguard-style peer factory: the server
-- generates the peer keypair and seals the private key at rest so that the
-- `.conf` and QR code can be regenerated later. Private keys NEVER touch the
-- network in plaintext apart from the initial download response.

ALTER TABLE peers ADD COLUMN private_key_sealed BLOB;
