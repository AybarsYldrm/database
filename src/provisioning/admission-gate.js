'use strict';

const { EventEmitter } = require('node:events');

// Who may reach this database, and when.
//
// The ordering requirement this implements is stated most simply as: *nothing talks to the
// database until the identity provider has.* Not "should not" -- cannot. The reason is that
// every other service in the stack gets its authority from the IdP, so a database that is
// reachable before the IdP is up is a database answering authorisation questions nobody has
// been able to ask yet. In practice that gap is where a database grows its own parallel
// identity system: a local user table, a static password, an allow-list maintained by hand.
// Each of those is a second source of truth about who someone is, and a second source of truth
// about identity is the thing Zero Trust exists to remove (NIST SP 800-207 §2.1 -- one policy
// decision point, not one per resource).
//
// So the database starts SEALED. It has an ephemeral, self-signed TLS identity generated at
// boot and never written anywhere, good for exactly one thing: letting the IdP reach the
// control plane. It cannot issue certificates, it does not know any principals, and the data
// plane refuses everyone.
//
// Three states, and the transitions between them are the whole design:
//
//   SEALED       ephemeral bootstrap identity. Only the control-plane handshake is reachable.
//                  |
//                  |  the IdP authenticates with the bootstrap secret and installs a server
//                  |  certificate + key issued from ITS root, plus the trust anchors
//                  v
//   PROVISIONED  the real server identity is live, held IN MEMORY ONLY and on a hold timer.
//                Enrolment is reachable to the IdP alone. Everyone else is still refused.
//                  |
//                  |  the IdP comes back on a mutually authenticated connection, presenting
//                  |  the client certificate it holds for itself
//                  v
//   OPEN         normal operation. Enrolment and the data plane are reachable under the usual
//                policy, and the IdP is now the attestor for everyone who comes after.
//
// If the second step never happens the hold expires, the provisioned material is wiped, and the
// database returns to SEALED. That timer is what makes the window a window: a server identity
// installed by someone who then vanishes is either a failed deployment or an attacker who got
// one message through, and both want the same response.
//
// The private key never touches disk in any state. A restart re-seals and the IdP provisions
// again, which costs one round trip and removes the file that a backup, a container image or a
// misconfigured volume mount would otherwise carry off.

const STATES = Object.freeze({
  SEALED: 'sealed',
  PROVISIONED: 'provisioned',
  OPEN: 'open',
});

const DEFAULT_HOLD_MS = 120_000;

/**
 * A denial that the transport can turn into a status code, whether or not @fitfak/grpc is
 * loadable in this process. The gate is required by tests that run without the transport, and
 * a module that cannot be required in isolation is a module that cannot be tested in isolation.
 */
function denial(statusName, message) {
  try {
    // eslint-disable-next-line global-require
    const { GrpcError, GRPC_STATUS } = require('@fitfak/grpc');
    return new GrpcError(GRPC_STATUS[statusName], message);
  } catch (_) {
    const err = new Error(message);
    err.name = 'AdmissionDenied';
    err.grpcStatusName = statusName;
    return err;
  }
}

class AdmissionGate extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {string}   opts.controlPrincipal  the principal allowed through while sealed -- the IdP
   * @param {string}  [opts.controlSpiffeId]  its SPIFFE ID, checked in addition to the name when set
   * @param {number}  [opts.holdMs]           how long a provisioned identity survives uncommitted
   * @param {function}[opts.installIdentity]  ({key, cert, ca}) => void -- swaps the live TLS context
   * @param {function}[opts.restoreIdentity]  () => void -- puts the bootstrap identity back
   * @param {object}  [opts.logger]
   */
  constructor({
    controlPrincipal,
    controlSpiffeId = null,
    holdMs = DEFAULT_HOLD_MS,
    installIdentity = null,
    restoreIdentity = null,
    logger = null,
  } = {}) {
    super();
    if (!controlPrincipal) {
      throw new Error('fitdb gate: createAdmissionGate requires a controlPrincipal -- the one identity '
        + 'allowed through while the database is sealed');
    }
    this.controlPrincipal = controlPrincipal;
    this.controlSpiffeId = controlSpiffeId;
    this.holdMs = holdMs;
    this._installIdentity = installIdentity;
    this._restoreIdentity = restoreIdentity;
    this._log = logger;

    this._state = STATES.SEALED;
    this._holdTimer = null;
    this._provisionedAt = 0;
    this._openedAt = 0;
    // Metadata about the live identity -- never the key. Something has to be able to answer
    // "what is installed" for diagnostics, and the answer must not be a copy of the secret.
    this._identityInfo = null;
  }

  get state() { return this._state; }
  get isOpen() { return this._state === STATES.OPEN; }
  get isSealed() { return this._state === STATES.SEALED; }

  status() {
    return {
      state: this._state,
      controlPrincipal: this.controlPrincipal,
      controlSpiffeId: this.controlSpiffeId,
      provisionedAt: this._provisionedAt || null,
      openedAt: this._openedAt || null,
      holdExpiresAt: this._holdTimer && this._provisionedAt ? this._provisionedAt + this.holdMs : null,
      identity: this._identityInfo,
    };
  }

  // ---- transitions --------------------------------------------------------------------------

  /**
   * The IdP has handed over the server identity it minted for this database.
   *
   * `key` and `cert` go straight into the live TLS context and are not retained here; what is
   * kept is the subject/expiry/fingerprint, which is what an operator needs and an attacker
   * does not. The hold timer starts now.
   */
  provision({ key, cert, ca, info = null }) {
    if (this._state === STATES.OPEN) {
      // Re-provisioning an open database is a rotation, not a bootstrap, and rotation has its
      // own path (rotateServerCertificate) that does not touch admission. Conflating them would
      // let a routine certificate renewal re-arm the hold timer and re-seal a live database.
      throw denial('FAILED_PRECONDITION',
        'this database is already open; use certificate rotation rather than re-provisioning');
    }
    if (typeof this._installIdentity !== 'function') {
      throw new Error('fitdb gate: no installIdentity callback was configured, so a provisioned '
        + 'server identity has nowhere to go');
    }

    this._installIdentity({ key, cert, ca });
    this._identityInfo = info;
    this._provisionedAt = Date.now();
    this._setState(STATES.PROVISIONED);

    this._armHold();
    this._log?.warn?.({
      holdMs: this.holdMs,
      subject: info?.subject,
      notAfter: info?.notAfter,
      msg: 'server identity provisioned by the control plane; held in memory pending the '
        + "identity provider's mutually authenticated connection",
    });
    this.emit('provisioned', { at: this._provisionedAt, info });
    return this;
  }

  /**
   * The control principal has completed a mutually authenticated connection. This is the
   * commit: the hold timer is cancelled and the database opens to everyone else.
   *
   * Called from the principal-resolution path, so it runs on every request the IdP makes and
   * has to be cheap and idempotent -- hence the early return rather than a guard that throws.
   */
  commit(peerPrincipalId) {
    if (this._state === STATES.OPEN) return false;
    if (this._state !== STATES.PROVISIONED) return false;
    if (peerPrincipalId !== this.controlPrincipal) return false;

    this._clearHold();
    this._openedAt = Date.now();
    this._setState(STATES.OPEN);
    this._log?.info?.({
      principal: peerPrincipalId,
      heldMs: this._openedAt - this._provisionedAt,
      msg: 'identity provider connected with mutual TLS; database open to all principals',
    });
    this.emit('opened', { at: this._openedAt, principal: peerPrincipalId });
    return true;
  }

  /**
   * Back to square one. Used by the hold expiry and available to an operator who wants to shut
   * the door without restarting -- an incident where the IdP is believed compromised is exactly
   * the case where "stop admitting anyone until this is sorted out" is the correct action.
   */
  seal(reason = 'sealed by request') {
    if (this._state === STATES.SEALED) return false;
    this._clearHold();
    const previous = this._state;
    this._identityInfo = null;
    this._provisionedAt = 0;
    this._openedAt = 0;
    this._setState(STATES.SEALED);
    // Putting the bootstrap identity back matters: leaving the IdP-issued certificate installed
    // on a sealed database means a peer that reaches it still sees a certificate chaining to a
    // real trust anchor, which reads like a working service rather than one that has locked
    // itself down.
    if (typeof this._restoreIdentity === 'function') {
      try { this._restoreIdentity(); }
      catch (err) { this._log?.error?.({ error: err.message, msg: 'could not restore the bootstrap identity' }); }
    }
    this._log?.warn?.({ from: previous, reason, msg: 'database sealed' });
    this.emit('sealed', { reason, from: previous });
    return true;
  }

  // ---- enforcement --------------------------------------------------------------------------

  /**
   * The check every data-plane request passes through. Throws unless the database is open or
   * the caller is the control principal.
   */
  assertAdmits(principalId) {
    if (this._state === STATES.OPEN) return;
    if (principalId && principalId === this.controlPrincipal) return;
    throw denial('FAILED_PRECONDITION',
      `this database is ${this._state}: it does not serve any principal until '${this.controlPrincipal}' `
      + 'has connected. This is not a transient error -- bring up the identity provider first.');
  }

  /**
   * Wraps a principal resolver so that admission is checked in the one place every
   * authenticated request already goes through, and so that the IdP's first mutually
   * authenticated request is what commits the gate.
   *
   * Wrapping rather than asking each handler to call assertAdmits() is deliberate: a check that
   * has to be repeated at every entry point is a check that will be missing from the entry point
   * added next year.
   */
  wrapPrincipalResolver(resolvePrincipal) {
    return (peer) => {
      const principal = resolvePrincipal(peer);
      this._verifyControlIdentity(principal);
      this.commit(principal?.id);
      this.assertAdmits(principal?.id);
      return principal;
    };
  }

  /**
   * Wraps an attestor so that enrolment is refused while the database is not open, except for
   * the control principal itself.
   *
   * Without this, a service could obtain a certificate during the bootstrap window and then
   * connect the moment the gate opened -- which is the same escalation the gate exists to
   * prevent, just deferred by a few seconds.
   */
  wrapAttestor(attestor) {
    if (!attestor) return attestor;
    return {
      name: attestor.name,
      attest: async (context) => {
        const grant = await attestor.attest(context);
        if (this._state !== STATES.OPEN && grant.principal !== this.controlPrincipal) {
          throw denial('FAILED_PRECONDITION',
            `enrolment is closed until '${this.controlPrincipal}' has connected`);
        }
        return grant;
      },
    };
  }

  /**
   * The control principal's certificate must also carry the SPIFFE ID we expect, when one is
   * configured. The principal name comes from the allow-list, which is a policy table; the
   * SPIFFE ID comes from the certificate, which is a cryptographic claim. Requiring both means
   * an attacker who can edit configuration still cannot become the IdP, and one who can mint a
   * certificate still has to be listed.
   */
  _verifyControlIdentity(principal) {
    if (!this.controlSpiffeId) return;
    if (!principal || principal.id !== this.controlPrincipal) return;
    // eslint-disable-next-line global-require
    const spiffe = require('./spiffe');
    const presented = spiffe.fromCertificate(principal.certificate);
    if (!presented || presented.uri !== this.controlSpiffeId) {
      throw denial('PERMISSION_DENIED',
        `'${this.controlPrincipal}' must present the SPIFFE ID ${this.controlSpiffeId}, got `
        + `${presented ? presented.uri : 'none'}`);
    }
  }

  // ---- internals ----------------------------------------------------------------------------

  _setState(state) {
    const previous = this._state;
    this._state = state;
    if (previous !== state) this.emit('stateChanged', { from: previous, to: state });
  }

  _armHold() {
    this._clearHold();
    this._holdTimer = setTimeout(() => {
      this._holdTimer = null;
      this.seal(`the identity provider did not complete its mutually authenticated connection within ${this.holdMs}ms`);
    }, this.holdMs);
    // The hold must not be the reason a process stays alive. A database whose only remaining
    // work is "wait to give up on a bootstrap that never happened" should exit with everything
    // else, not linger.
    if (typeof this._holdTimer.unref === 'function') this._holdTimer.unref();
  }

  _clearHold() {
    if (this._holdTimer) { clearTimeout(this._holdTimer); this._holdTimer = null; }
  }

  /** Releases the hold timer. Called by the server on shutdown. */
  close() { this._clearHold(); }
}

function createAdmissionGate(options) { return new AdmissionGate(options); }

module.exports = { AdmissionGate, createAdmissionGate, GATE_STATES: STATES, DEFAULT_HOLD_MS };
