# Bundled TPM vendor root CAs

Each subdirectory holds the PEM-encoded **root** CA certificate(s) for one TPM
vendor's Endorsement Key signing hierarchy. At build time
[`build.rs`](../build.rs) concatenates every `*.pem` under a vendor directory
into `OUT_DIR/<vendor>.pem`, and [`vendor.rs`](../src/vendor.rs) embeds those
via `include_str!`. Each vendor is independently selectable
(`VendorTrustStore::with_vendor(Vendor::Infineon)`), so a fleet can trust only
the vendors it actually deploys.

Layout:

```
vendor-roots/
  infineon/   Infineon OPTIGA TPM RSA/ECC roots
  nuvoton/    Nuvoton NPCT root CAs
  st/         STMicroelectronics TPM ECC roots
  intel/      Intel PTT (firmware TPM) roots
```

The directories are committed empty (`.gitkeep`). **Nothing is trusted by
default** — until you provision a root, any EK chain that would rely on it is
rejected fail-closed.

## Provisioning a root

Use [`scripts/ferrogate-ca.sh`](../../../scripts/ferrogate-ca.sh). Treat adding
a root as a trust decision: always confirm the fingerprint against the value
the vendor publishes (or the TCG mirror) before committing.

1. **Obtain** the vendor's root CA certificate (PEM or DER). Convert DER to PEM
   if needed: `openssl x509 -inform DER -in root.der -out root.pem`.

2. **Inspect** it and note the fingerprint:

   ```sh
   scripts/ferrogate-ca.sh fingerprint root.pem
   ```

3. **Compare** the printed `sha256` against the vendor's published value. Do
   not skip this — it is the whole basis of the trust.

4. **Install** it, pinning the expected fingerprint so the tool refuses a
   mismatch:

   ```sh
   scripts/ferrogate-ca.sh add infineon root.pem \
       --fingerprint sha256:AB:CD:... \
       --name optiga-ecc-root
   ```

   The tool validates the cert is a self-signed CA, checks the fingerprint, and
   writes a canonicalized PEM into `vendor-roots/infineon/optiga-ecc-root.pem`.

5. **Rebuild** so the new root is embedded:

   ```sh
   cargo build -p ferro-attest
   ```

6. **Commit** the new PEM. Code review is the second pair of eyes on the trust
   decision; the fingerprint should be visible in the diff and the PR
   description.

## Inspecting what's trusted

```sh
scripts/ferrogate-ca.sh list      # every installed root + fingerprint, by vendor
scripts/ferrogate-ca.sh verify    # re-check each installed root parses and is a CA
```
