'use strict';

const { createAdmissionGate, GATE_STATES } = require('../src/provisioning/admission-gate');

// The ordering rule, on its own, without a transport in the way.
//
// The rule is: nothing reaches this database until the identity provider has. Everything below
// is a way that rule could be got around, checked to make sure it is not:
//
//   - connect before anyone provisions anything                    -> refused
//   - connect while the IdP is mid-bootstrap                       -> refused
//   - be the IdP by name, but present the wrong workload identity  -> refused
//   - enrol during the bootstrap window and connect once it opens  -> refused at enrolment
//   - provision, then vanish                                       -> the gate re-seals itself
//
// The last one is the one worth having a timer for. An installed server identity that nobody
// ever commits is either a deployment that failed halfway or a single message an attacker got
// through, and both want the door shut again rather than left ajar indefinitely.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function refuses(label, fn) {
  let threw = false;
  try { fn(); } catch (_) { threw = true; }
  check(label, threw);
}

const IDP = 'idp-service';
const IDP_SPIFFE = 'spiffe://fitfak.net/service/idp';

function makeGate(overrides = {}) {
  const installed = [];
  const restored = [];
  const gate = createAdmissionGate({
    controlPrincipal: IDP,
    holdMs: 50,
    installIdentity: (identity) => installed.push(identity),
    restoreIdentity: () => restored.push(Date.now()),
    ...overrides,
  });
  return { gate, installed, restored };
}

const peerFor = (id, altNames = []) => ({ certificate: { subject: { CN: id }, altNames } });

async function main() {
  console.log('\n1. A fresh gate is sealed and serves nobody');

  {
    const { gate } = makeGate();
    check('the initial state is sealed', gate.state === GATE_STATES.SEALED);
    check('it does not report itself open', !gate.isOpen);
    refuses('an ordinary principal is refused', () => gate.assertAdmits('smtp-service'));
    refuses('an unauthenticated caller is refused', () => gate.assertAdmits(null));
    // The one exception, and the reason there is one: the IdP has to be able to get in to
    // provision the thing that lets everyone else in.
    gate.assertAdmits(IDP);
    check('the control principal is admitted even while sealed', true);
    gate.close();
  }

  console.log('\n2. Provisioning installs the identity but does not open the door');

  {
    const { gate, installed } = makeGate();
    gate.provision({
      key: 'KEY', cert: 'CERT', ca: 'ANCHOR',
      info: { subject: 'CN=fitdb', notAfter: Date.now() + 86400000 },
    });
    check('the state moved to provisioned', gate.state === GATE_STATES.PROVISIONED);
    check('the identity reached the TLS context', installed.length === 1 && installed[0].cert === 'CERT');
    refuses('another service is STILL refused', () => gate.assertAdmits('smtp-service'));
    check('a hold expiry is published', gate.status().holdExpiresAt > Date.now());
    // Nothing that could be exfiltrated by reading the gate's own state.
    check('the private key is not retained in the gate', !JSON.stringify(gate.status()).includes('KEY'));
    gate.close();
  }

  console.log("\n3. The identity provider's mTLS connection is the commit");

  {
    const { gate } = makeGate();
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });

    check('a non-control principal cannot commit', gate.commit('smtp-service') === false);
    check('the state is unchanged by that attempt', gate.state === GATE_STATES.PROVISIONED);

    check('the control principal commits', gate.commit(IDP) === true);
    check('the state is open', gate.state === GATE_STATES.OPEN);
    gate.assertAdmits('smtp-service');
    check('everyone else is admitted now', true);
    check('committing twice is a harmless no-op', gate.commit(IDP) === false);
    gate.close();
  }

  console.log('\n4. Committing goes through the principal resolver, so no handler can forget it');

  {
    const { gate } = makeGate();
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });
    const resolve = gate.wrapPrincipalResolver((peer) => ({
      id: peer.certificate.subject.CN, certificate: peer.certificate,
    }));

    refuses('a wrapped resolve refuses a stranger while provisioned', () => resolve(peerFor('smtp-service')));
    const principal = resolve(peerFor(IDP));
    check('the control principal resolves', principal.id === IDP);
    check('and that resolution opened the gate', gate.state === GATE_STATES.OPEN);
    check('the stranger now resolves too', resolve(peerFor('smtp-service')).id === 'smtp-service');
    gate.close();
  }

  console.log('\n5. Holding the right name is not enough when a SPIFFE ID is pinned');

  {
    const { gate } = makeGate({ controlSpiffeId: IDP_SPIFFE });
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });
    const resolve = gate.wrapPrincipalResolver((peer) => ({
      id: peer.certificate.subject.CN, certificate: peer.certificate,
    }));

    refuses('CN=idp-service with no SPIFFE ID is refused', () => resolve(peerFor(IDP)));
    refuses('CN=idp-service with the wrong SPIFFE ID is refused',
      () => resolve(peerFor(IDP, ['URI:spiffe://fitfak.net/service/smtp'])));
    check('the gate stayed shut through both attempts', gate.state === GATE_STATES.PROVISIONED);

    resolve(peerFor(IDP, [`URI:${IDP_SPIFFE}`]));
    check('the right name AND the right identity opens it', gate.state === GATE_STATES.OPEN);
    gate.close();
  }

  console.log('\n6. Enrolment is closed during the bootstrap window');

  {
    const { gate } = makeGate();
    const attestor = gate.wrapAttestor({
      name: 'test',
      attest: async ({ request }) => ({ principal: request.serviceName, subject: { CN: request.serviceName } }),
    });
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });

    let denied = false;
    try { await attestor.attest({ request: { serviceName: 'dns-resolver' } }); }
    catch (_) { denied = true; }
    check('another service cannot enrol before the gate opens', denied);

    const idpGrant = await attestor.attest({ request: { serviceName: IDP } });
    check('the control principal can still enrol', idpGrant.principal === IDP);

    gate.commit(IDP);
    const grant = await attestor.attest({ request: { serviceName: 'dns-resolver' } });
    check('once open, enrolment works normally', grant.principal === 'dns-resolver');
    gate.close();
  }

  console.log('\n7. A provisioning that is never committed re-seals itself');

  {
    const { gate, restored } = makeGate();
    const sealedEvents = [];
    gate.on('sealed', (event) => sealedEvents.push(event));

    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });
    await new Promise((resolve) => setTimeout(resolve, 80));

    check('the gate re-sealed when the hold expired', gate.state === GATE_STATES.SEALED);
    check('the bootstrap identity was put back', restored.length === 1);
    check('the reason says what happened', /did not complete/.test(sealedEvents[0].reason));
    refuses('and the control principal must provision again', () => gate.assertAdmits('smtp-service'));
    gate.close();
  }

  console.log('\n8. Committing cancels the hold, so an open database does not re-seal under it');

  {
    const { gate } = makeGate();
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });
    gate.commit(IDP);
    await new Promise((resolve) => setTimeout(resolve, 80));
    check('still open well past the hold window', gate.state === GATE_STATES.OPEN);
    gate.close();
  }

  console.log('\n9. Re-provisioning an open database is refused');

  {
    const { gate } = makeGate();
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });
    gate.commit(IDP);
    // Otherwise a routine certificate rotation, arriving on the control plane, would re-arm the
    // hold timer against a database that is serving traffic and re-seal it two minutes later.
    refuses('rotation must not travel through the bootstrap path',
      () => gate.provision({ key: 'K2', cert: 'C2', ca: 'A2' }));
    check('the database is still open', gate.state === GATE_STATES.OPEN);
    gate.close();
  }

  console.log('\n10. An operator can seal a live database');

  {
    const { gate, restored } = makeGate();
    gate.provision({ key: 'KEY', cert: 'CERT', ca: 'ANCHOR' });
    gate.commit(IDP);
    gate.seal('the identity provider is believed compromised');
    check('the state is sealed again', gate.state === GATE_STATES.SEALED);
    check('the bootstrap identity is back', restored.length === 1);
    refuses('and traffic stops', () => gate.assertAdmits('smtp-service'));
    gate.close();
  }

  console.log(`\nOK - admission gate: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message); process.exit(1); },
);
