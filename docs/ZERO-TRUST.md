# The sealed database

## The whole thing, in order

Everything in this system takes its identity from the identity provider, and the ordering below
is not a convention -- it is what makes that true rather than aspirational.

```
1.  IdP starts            Opens its CA from the local encrypted vault. Asks nobody anything:
                          the vault is beside it, so there is no network dependency to satisfy.

2.  Database starts       SEALED. No CA, no server certificate anyone would trust, no principals.
                          It wears an ephemeral self-signed certificate generated at boot and
                          never written down. Only the control plane is reachable.

3.  Control plane         The IdP proves itself with the shared control secret, bound to the TLS
                          exporter (RFC 9266), and hands over a server certificate it issued from
                          its own root, the matching key, and the trust anchors.
                          -> the database now has a SERVER identity. Still not open.

4.  mTLS, upgraded        The IdP comes back presenting its own CLIENT certificate, issued by the
                          same root. The database validates it, sees the SPIFFE ID it was told to
                          expect, and OPENS.

5.  Everyone else         Services enrol: authenticate, receive a SPIFFE identity, upgrade to
                          mTLS. The database never signs anything -- it is a Registration
                          Authority and delegates every signature to the IdP.

6.  Steady state          Every connection is mTLS, every identity is a SPIFFE ID in a URI SAN,
                          every certificate is short-lived and renews itself.
```

Steps 3 and 4 are separate on purpose, with a hold timer between them. Installing a certificate
is not the same as proving you can use it: if the IdP stops after step 3, the material is dropped
and the database re-seals. That is either a deployment that failed halfway or a single message an
attacker got through, and both want the door shut again.

Neither process requires the other to be running when it starts. The database boots sealed and
waits; the IdP boots, buffers its writes, and connects in the background. `scripts/run-local-stack.sh`
brings both up and waits for step 4 to actually happen.

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

The runnable version of all of this is `bin/db-server.js` — the program, not an example of one:

```
npx fitdb-server            # or: node bin/db-server.js
```

It contains no application code and nowhere to put any. No service names, no schemas, no seeded
principals: everything this database serves is registered at runtime, from the admin panel or by
the identity provider, and lives in state rather than in source. A server file that lists its
services is a server that must be edited and restarted to gain one — and operators who have to
restart a database to add a service stop adding services one at a time. They raise `maxUses` on an
existing credential instead, and a single-shot bootstrap secret quietly becomes a standing key.

### Neither process has to start first

The two used to be wired together by hand: copy the control secret out of the database's stdout,
invent a registration-authority client id and secret, enter five values on both sides, and get an
unreadable TLS error when any of them was mistyped.

Now both read and write one directory (`src/pairing.js`):

```
  <pairing>/database.json     written by the database:  target, control secret, bootstrap fingerprint
  <pairing>/idp.json          written by the IdP:       issuance URL, RA credentials, panel OAuth
                                                        client, root certificate
```

Only the directory is configurable, with `FITFAK_PAIRING_DIR`, and only when the two run as
different users. The root CA **key** is never written there — the only PKI material in the
directory is the root's certificate and its fingerprint, both public.

Logically the IdP comes first: it is the certificate authority and this database cannot open
without it. But neither process requires the other to be running when it starts. The database boots
sealed and waits; the IdP boots, buffers its writes, and connects in the background. Whichever
starts first waits for the other.

### Who gets into the admin panel

Two ways, and the difference between them is the point.

1. **The identity provider**, which is the everyday path. The operator clicks through, signs in
   there with whatever it requires that day, and comes back with an authorization code. The IdP
   decides who is an administrator; the panel only checks the answer — a `fitdb:admin` scope *and*
   an admin role, checked separately, because a consent screen can grant the first and must never
   be able to grant the second.
2. **The startup token**, which is break-glass. The IdP is a separate process that can be down, and
   when it is, this database is the thing an operator most needs to look at.

The panel displays which of the two is holding the door open, because they are not equivalent.

### A branch application in one call

`joinAsService` is everything `examples/app-client.js` demonstrates, as a supported call:

```js
const { joinAsServiceWhenReady } = require('@fitfak/database');

const service = await joinAsServiceWhenReady({ serviceName: 'dns-resolver', roles: ['reader', 'writer'] });
const records = service.db.collection('records');
```

`examples/app-client.js` is still worth reading to understand what happens — and worth **not**
copying into an application. It is about 200 lines, every application needed its own copy, and
every copy is a place for one step to be dropped. The steps that get dropped are predictable, and
none of them fail in a way that points back at the step:

| Dropped | What it looks like instead |
|---|---|
| Persisting the certificate | Every restart enrols again, so the single-shot secret has to become a standing credential. Nothing looks wrong until someone asks why it has been used forty times. |
| Renewing | Works perfectly for hours, then a TLS handshake failure that never mentions expiry. |
| Pinning the **root**, not the leaf | Breaks daily — the server certificate is regenerated on every boot, which is the point of the sealed bootstrap. |
| Retrying while sealed | The application cannot be started before the IdP, because it treats a normal ordering as fatal. |

Two things it deliberately will not do: invent an enrolment secret, or read one from the pairing
directory. That secret is one service's credential, shown once in the admin panel — a secret
readable from a shared directory would be one every process on the host could enrol with, and the
identity model would reduce to "can you read /var/lib/fitfak".

`joinAsService` throws on a sealed database; `joinAsServiceWhenReady` retries. They are separate
because they mean different things: a one-shot task should exit when misconfigured, a long-running
service should survive being started first. Only the sealed case is retried — retrying a wrong
secret would turn a clear failure into a service that never starts and never says why.

A worked version is `examples/branch-service.js`.

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
