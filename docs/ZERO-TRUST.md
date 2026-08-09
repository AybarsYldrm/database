# The sealed database

How this database gets an identity, who is allowed to talk to it, and why the order matters.

This document covers the fitdb side. The certificate authority, the short-lived issuance model
and the login flows live in the IdP; see `docs/BEYONDCORP.md` there.

---

## The problem this solves

A database that comes up before the identity provider has to answer "who is this?" on its own.
Every design that does so ends up in the same place: a local user table, a static password, or an
allow-list edited by hand. That is a second source of truth about identity sitting next to the
one that is supposed to be authoritative — and while the IdP is down, it is the *only* one.

NIST SP 800-207 §2.1 is explicit that a Zero Trust architecture has one policy decision point,
not one per resource. So this database has none of its own. It cannot issue a certificate, it has
no CA key, it does not know any principal until it is told, and it starts out refusing everyone.

---

## Three states

```
                    ephemeral self-signed certificate, generated at boot,
                    never written to disk. Only the control plane is reachable.
        ┌────────────────────────────────────────────────────────────────┐
        │                          SEALED                                │
        └────────────────────────────────────────────────────────────────┘
                                    │
                                    │  IdP authenticates with the control secret
                                    │  and installs: server certificate + key +
                                    │  trust anchors, all minted from its root
                                    ▼
        ┌────────────────────────────────────────────────────────────────┐
        │                       PROVISIONED                              │
        │   real server identity live, held in memory, hold timer armed  │
        │   enrolment and the data plane still refuse everyone but IdP   │
        └────────────────────────────────────────────────────────────────┘
                        │                             │
   IdP connects with    │                             │  hold expires
   its client cert      │                             │  (default 120 s)
                        ▼                             ▼
        ┌───────────────────────────┐   material dropped, bootstrap identity
        │           OPEN            │   restored, back to SEALED
        │  normal operation for all │
        └───────────────────────────┘
```

The hold timer is what makes the window a window. A server identity installed by someone who then
disappears is either a deployment that failed halfway or an attacker who got one message through,
and both want the same response.

`AdmissionGate.seal()` is available at runtime: an incident where the IdP is believed compromised
is exactly the case where "stop admitting anyone until this is sorted out" is the right action,
and it should not require a restart.

---

## The bootstrap exchange

```
IdP                                                          fitdb (SEALED)
 │                                                                   │
 │  1. TLS handshake. The server presents an ephemeral self-signed    │
 │     certificate. Nothing is authenticated yet by TLS alone.        │
 │ ─────────────────────────────────────────────────────────────────▶│
 │                                                                   │
 │  2. GetBootstrapChallenge { clientNonce }                          │
 │ ─────────────────────────────────────────────────────────────────▶│
 │                                                                   │
 │     { serverNonce, serverConfirmation = HMAC(secret,               │
 │         "confirm" ‖ clientNonce ‖ serverNonce ‖ tls-exporter) }    │
 │ ◀─────────────────────────────────────────────────────────────────│
 │                                                                   │
 │  3. VERIFY serverConfirmation.  ⚠ NOTHING SENSITIVE HAS MOVED YET. │
 │     If this fails the exchange stops here, having disclosed        │
 │     nothing. This is the step a naive implementation skips —       │
 │     and skipping it hands a private key to whoever answered.       │
 │                                                                   │
 │  4. InstallServerIdentity {                                        │
 │        serverNonce, timestamp,                                     │
 │        proof = HMAC(secret, "install" ‖ serverNonce ‖ timestamp    │
 │                     ‖ tls-exporter ‖ SHA-256(material)),           │
 │        certPem, privateKeyPem, chainPem, trustAnchorsPem,          │
 │        controlSpiffeId }                                           │
 │ ─────────────────────────────────────────────────────────────────▶│
 │                                                    installs into   │
 │                                                    the live TLS    │
 │                                                    context;        │
 │                                                    state =         │
 │                                                    PROVISIONED     │
 │     { installed: true, holdExpiresAt }                             │
 │ ◀─────────────────────────────────────────────────────────────────│
 │                                                                   │
 │  5. New connection, mutual TLS, IdP's own client certificate       │
 │     carrying spiffe://<domain>/service/idp                         │
 │ ─────────────────────────────────────────────────────────────────▶│
 │                                            principal resolves →    │
 │                                            gate.commit() → OPEN    │
 │                                                                   │
 │  6. Everyone else may now enrol and connect.                       │
```

### Why both directions authenticate

The client→server direction is obvious: without it, anyone who can reach the port installs a
server identity and the database serves an attacker's certificate.

The server→client direction is the one that gets forgotten, and forgetting it is fatal. The
bootstrap message **carries a private key**. An interceptor who terminates TLS receives the
certificate and key the IdP meant for the database, and can impersonate the database from then on.
Step 3 exists to make the IdP refuse to send it.

Both proofs are HMACs over a transcript that includes the RFC 9266 `tls-exporter` value. An
interceptor holds two TLS sessions with two different exporter values, so a proof computed for one
leg does not verify on the other — which is what stops either proof from being forwarded.

### Why the transcript covers the material

Without `SHA-256(material)` in the transcript, an interceptor who cannot forge a proof could still
keep a valid one and substitute a certificate and key of their own choosing. The proof would say
"the IdP authorised an installation" — true — and say nothing about *what* was installed.

---

## Replay analysis

| Captured message | Why replay fails |
|---|---|
| `GetBootstrapChallenge` | Carries no secret. A replay gets a fresh `serverNonce` bound to the replayer's own session, which they cannot then use. |
| `serverConfirmation` | Bound to `tls-exporter`. Replaying it on a different connection produces a different exporter value, so the IdP's check fails. |
| `InstallServerIdentity` | Three independent barriers: the `serverNonce` is burned on first use (before any other check, so a rejected attempt does not leave a live nonce); the timestamp is outside the 60 s window; and the exporter value belongs to a session the replayer does not hold. |
| `Enroll` proof | Same construction (`enrolmentTranscript`): nonce, timestamp, exporter, plus the CSR fingerprint so a valid proof cannot be paired with a substituted public key. |
| A short-lived certificate | Expires in minutes. A stolen credential is worth having for the remainder of its lifetime and then nothing. |

Application-layer replay of *data-plane* requests is out of scope here and is handled by DTLS/TLS
sequence numbers and by the capability tokens' own single-use semantics — not by certificate
semantics, which is deliberate: encoding anti-replay into a certificate is the kind of proprietary
extension this design avoids.

---

## Threat model

**In scope**

| Threat | Mitigation |
|---|---|
| A service connects before the IdP is up and gets an authorisation decision from a database that cannot make one | The gate. The data plane refuses every principal but the control principal until OPEN. |
| A service enrols during the bootstrap window and walks in when the gate opens | `wrapAttestor` closes issuance to everyone but the control principal while not OPEN. |
| Someone reaches the port and installs their own server identity | Control secret + channel-bound proof over the material. |
| An interceptor collects the private key the IdP sends | Server confirmation, verified *before* transmission. |
| A CN collision — a second CA, or a renamed service — becomes an impersonation | Allow-list entries pin the expected SPIFFE ID; the principal resolver refuses a mismatch. |
| A certificate from another trust domain validates against a chained anchor | `trustDomain` check in the principal resolver refuses it regardless. |
| A peer names itself in its CSR | Identity comes from the attestor's grant, never the CSR; `assertIdentityMatchesGrant` refuses any disagreement rather than narrowing to the intersection. |
| A peer omits the granted SPIFFE ID to shed the authorising field | `assertSpiffeMatchesGrant` requires the granted ID to be present, exactly once. |
| A copy of the data directory | Records are encrypted under a key derived from the DDK, reachable only through a KeyProvider holding the root secret. |
| A stale bootstrap credential used repeatedly | `maxUses: 1` by default; renewal goes through mTLS re-enrolment and never touches the secret again. |

**Explicitly out of scope**

- **A memory dump of a live process.** Every key this database holds is decrypted into its heap
  when used. The answer is a signer that never releases the key — a TPM, PKCS#11, or a cloud KMS —
  not a different database. Saying otherwise would overstate what encryption at rest buys.
- **A compromised IdP.** It is the root of trust by construction. `seal()` is the containment
  mechanism, not a preventative one.
- **Traffic analysis.** Blind indexes hide values, not access patterns.

---

## Recommended defaults

| Setting | Default | Why |
|---|---|---|
| `admission.holdMs` | 120 000 | Long enough for a slow IdP start, short enough that an uncommitted install does not linger. |
| `minVersion` (TLS) | `TLSv1.3` | The channel binding both proofs depend on is the TLS 1.3 exporter. A downgrade silently weakens the replay protection. |
| `requestCert` / `rejectUnauthorized` | `true` / `false` | One port serves bootstrap and data plane. With `rejectUnauthorized: true` the handshake fails first and a service that has never enrolled has no way in. |
| `subjectField` | `spiffe` for new deployments | The only identity field nothing else can collide with. `CN` remains for existing allow-lists. |
| `requireSpiffeId` | `true` | Refuse certificates carrying no workload identity at all. |
| `maxUses` (enrolment secret) | 1 | A bootstrap secret that stays valid is a permanent backdoor next to the identity system. |
| Service certificate lifetime | 1 hour | Long enough that a failed renewal has room to retry; short enough that expiry is a real revocation mechanism. |
| Workload certificate lifetime | 5 minutes | The BeyondCorp default. Renewal at 50 % of lifetime, not 66 % — see below. |

### Why renewal at 50 % for short-lived certificates

With a 397-day certificate, two thirds of the lifetime leaves months of slack. With a five-minute
certificate it leaves 100 seconds, and a single slow CA round trip inside that window is an
outage. The enrolment service switches to 50 % automatically below a one-hour lifetime.

### Why notBefore is backdated 60 seconds

A certificate valid from the instant of issuance is rejected by any verifier whose clock is a
second behind, and clocks in a fleet are always a second behind something. Invisible at 397 days;
the difference between "works" and "fails intermittently across a third of the fleet" at five
minutes. Let's Encrypt and SPIRE both use 60 seconds.

---

## Component responsibilities

| Module | Owns | Explicitly does not |
|---|---|---|
| `provisioning/admission-gate.js` | The three-state machine, the hold timer, wrapping the resolver and attestor | Know anything about TLS or gRPC |
| `provisioning/control-plane-service.js` | The two-message handover, both proofs, nonce lifetime | Decide policy; it drives the gate |
| `provisioning/bootstrap-identity.js` | The throwaway boot certificate | Persist anything |
| `provisioning/enrollment-service.js` | Registration Authority: authenticate, decide identity, delegate signing | Sign anything |
| `provisioning/identity-binding.js` | Grant-vs-CSR comparison, SPIFFE binding | Touch the transport (so it is testable without it) |
| `provisioning/idp-ca-backend.js` | Carrying a CSR to the IdP for signature | Hold a key |
| `provisioning/spiffe.js` | The identity grammar, strictly | Decide who may hold which identity |
| `pki-vault.js` | CA material in the encrypted store, one intermediate per purpose | Be an HSM |
| `grpc/identity.js` | Certificate → principal → permissions | Validate the chain (the transport did) |

---

## Usage

### Running a sealed database

```js
const {
  createDatabaseServer, createEphemeralBootstrapIdentity, createIdpCaBackend,
  createSharedSecretAttestor, createRenewalAttestor, createCompositeAttestor, spiffe,
} = require('@fitfak/database');

const bootstrapIdentity = createEphemeralBootstrapIdentity({
  ssl: require('@fitfak/ssl'),
  commonName: 'db.fitfak.net',
  dnsNames: ['db.fitfak.net', 'localhost'],
});

const server = createDatabaseServer({
  baseDir: './fitdb',
  principals: {
    'idp-service': { roles: ['admin'], spiffeId: 'spiffe://fitfak.net/service/idp' },
  },
  trustDomain: 'fitfak.net',
  requireSpiffeId: true,

  admission: {
    controlPrincipal: 'idp-service',
    controlSpiffeId: 'spiffe://fitfak.net/service/idp',
    bootstrapSecret,          // shared with the IdP out of band
    bootstrapIdentity,
    holdMs: 120_000,
  },

  enrollment: {
    // No local CA. Signing is delegated to the IdP.
    caBackend: createIdpCaBackend({
      issuanceUrl: 'https://trust.fitfak.net/pki/ra/issue',
      clientId: 'fitdb-registration-authority',
      clientSecret: process.env.FITFAK_DB_RA_CLIENT_SECRET,
      spiffePrefix: 'spiffe://fitfak.net/service',
      trustAnchorsProvider: () => server.clientTrustAnchors || [],
    }),
    attestor: createCompositeAttestor([createSharedSecretAttestor({ enrolments })]),
    renewalAttestor: createRenewalAttestor({ trustDomain: 'fitfak.net' }),
  },
});

server.listen(51572, {
  host: '127.0.0.1',
  tls: {
    key: bootstrapIdentity.key,
    cert: bootstrapIdentity.cert,
    ca: bootstrapIdentity.ca,
    requestCert: true,
    rejectUnauthorized: false,
    minVersion: 'TLSv1.3',
  },
});
```

A full, commented version is `examples/db-server.js`.

### An ordinary application connecting

Nothing changes for services that are not the IdP. They enrol as before — the only difference is
that they will be refused with `FAILED_PRECONDITION` until the IdP has connected, and the message
says so.

```js
const { enroll, connectDatabase } = require('@fitfak/database');

const identity = await enroll({
  target: 'https://db.fitfak.net:51572',
  serviceName: 'smtp-service',
  csrProvider: createFitfakSslCsrProvider(),
  trust: { pinnedFingerprints: [rootFingerprint] },
  bootstrap: { secret: Buffer.from(process.env.ENROLMENT_SECRET, 'base64') },
  altNames: ['spiffe://fitfak.net/service/smtp', 'smtp-service'],
});

identity.startAutoRenewal();
const handle = await connectDatabase({ target, identity });
```

Once the IdP is up, new services do not need an out-of-band secret at all — they present an
IdP-issued token instead (`createIdpTokenAttestor`), which is the whole point of the composite
attestor: one endpoint, two eras.

---

## Future compatibility with SPIFFE/SPIRE

The identity model here is the SPIFFE one, not an approximation of it:

- IDs are `spiffe://<trust domain>/<path>` and are validated against the SPIFFE-ID grammar,
  including the cases most implementations get wrong (dot-segments, percent-encoding,
  non-canonical spellings).
- They live in the certificate's URI SAN, which is where SPIRE, Istio and every CNCF
  workload-identity implementation reads them.
- The trust domain is a first-class field, so federation is a comparison rather than a convention.

Migrating to SPIRE means replacing the *issuance* side — the attestors and the CA backend — while
the relying-party side (`createPrincipalResolver` with `subjectField: 'spiffe'`) keeps working
unchanged, because it is already reading a standard SPIFFE SVID. The pieces that would be
replaced are the ones this package deliberately kept behind interfaces.

What is *not* SPIFFE-compatible, and knowingly so: the enrolment protocol is this stack's own
rather than the SPIRE Node/Workload API. Adopting SPIRE would replace it. That is a reasonable
trade for a deployment of this size, and the SPIFFE-shaped identity means the replacement does
not have to touch anything that consumes an identity.
