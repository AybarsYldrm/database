'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const chain = require('../src/provisioning/chain');

// What a peer PRESENTS and what it TRUSTS.
//
// This replaces `chainPem.slice(0, -1)`, which appeared in three places and meant "everything
// except the last, because the last is the root". That is a positional claim about a list this
// process did not build, and it is wrong in both directions:
//
//   [intermediate, root]  -> drops the root. Right, by luck.
//   [intermediate]        -> drops the INTERMEDIATE. The peer gets a leaf whose issuer it has
//                            never seen, and the handshake fails with "unable to get local
//                            issuer certificate" -- which reads as a trust problem, not as a
//                            chain-assembly one, so the search starts in the wrong place.
//   [root, intermediate]  -> drops the intermediate. Silently broken.
//
// The one-element case is not hypothetical. The registration-authority backend falls back to
// `getTrustAnchors().chainPem` when an issuance response carries no chain, and the anchors are
// the ROOT ALONE -- so every service enrolling down that path presented a leaf with no
// intermediate to a peer that held only the root.
//
// The checks below are verified by OPENSSL rather than by this codebase's own parser. Producing
// bytes and then reading them back with the same code proves only that it is self-consistent;
// what matters is whether an independent implementation can build the path, because that is what
// a real peer does.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function hasOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; }
  catch (_) { return false; }
}

let ssl;
try { ssl = require('@fitfak/ssl'); } catch (_) {
  console.log('SKIP - chain assembly: @fitfak/ssl is not installed');
  process.exit(0);
}
if (!hasOpenssl()) {
  console.log('SKIP - chain assembly: openssl not found');
  process.exit(0);
}

const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fitdb-chain-'));
const write = (name, contents) => {
  const file = path.join(DIR, name);
  fs.writeFileSync(file, contents);
  return file;
};

/** Does openssl accept this leaf, given these anchors and this presented chain? */
function verifies(leafPem, presentedPem, anchorsPem) {
  const leaf = write('leaf.pem', leafPem);
  const untrusted = write('untrusted.pem', presentedPem);
  const anchors = write('anchors.pem', anchorsPem);
  try {
    execFileSync('openssl', ['verify', '-CAfile', anchors, '-untrusted', untrusted, leaf], { stdio: 'pipe' });
    return true;
  } catch (_) { return false; }
}

function main() {
  const root = ssl.generateEcRootCA({ commonName: 'FITFAK Chain Test Root' });
  const intermediate = ssl.generateEcIntermediateCA(root, { commonName: 'FITFAK Chain Test Issuing CA' });
  const rootPem = root.certPem || root.pem;
  const interPem = intermediate.certPem || intermediate.pem;

  // A leaf issued by the INTERMEDIATE -- the shape everything in this system actually uses.
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = kp.privateKey.export({ format: 'jwk' });
  const csr = ssl.generateCSR({
    keyType: 'ec',
    curveName: 'P-256',
    publicKeyBuf: Buffer.concat([
      Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url'),
    ]),
    privateKey: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
  }, [[ssl.oid.OIDs.commonName, 'dns-resolver']], []);
  const leafPem = ssl.issueCertificateFromCSR(csr, intermediate, {
    profile: 'tls-client', validityDays: 1,
    sans: [{ type: 'uri', value: 'spiffe://fitfak.net/service/dns-resolver' }],
  }).pem;

  console.log('\n1. Self-signed is decided by signature, not by name');

  {
    // Names can print identically and differ in encoding, or differ in print and be the same
    // name. A certificate is self-signed exactly when its own key validates its signature.
    check('the root is recognised as an anchor', chain.isSelfSigned(rootPem));
    check('the intermediate is not', !chain.isSelfSigned(interPem));
    check('the leaf is not', !chain.isSelfSigned(leafPem));
    // An unparseable entry must not land in the CA list, where a parse failure would resurface
    // much later as a validation failure somewhere else.
    check('garbage is not an anchor', !chain.isSelfSigned('-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----'));
  }

  console.log('\n2. Classification does not depend on order');

  {
    for (const [label, input] of [
      ['[intermediate, root]', [interPem, rootPem]],
      ['[root, intermediate]', [rootPem, interPem]],
      ['one concatenated blob', [`${interPem}\n${rootPem}`]],
    ]) {
      const result = chain.classifyChain(input);
      check(`${label}: one intermediate, one anchor`,
        result.intermediates.length === 1 && result.anchors.length === 1);
    }
  }

  console.log('\n3. openssl can build the path from what we present');

  {
    // The case that used to work by luck.
    check('[intermediate, root] verifies',
      verifies(leafPem, chain.presentationChain(leafPem, [interPem, rootPem]), rootPem));

    // THE CASE THAT USED TO BREAK. slice(0,-1) on a one-element chain drops the intermediate,
    // and the peer -- holding only the root -- cannot reach the leaf.
    check('[intermediate] alone verifies',
      verifies(leafPem, chain.presentationChain(leafPem, [interPem]), rootPem));

    // And the reverse order, which slice(0,-1) also got wrong.
    check('[root, intermediate] verifies',
      verifies(leafPem, chain.presentationChain(leafPem, [rootPem, interPem]), rootPem));

    // Proof the check measures something: without the intermediate, it must FAIL.
    check('a leaf with no intermediate does NOT verify',
      !verifies(leafPem, leafPem, rootPem));

    // And what the old code produced from a one-element chain was exactly that.
    const positional = [leafPem, ...[interPem].slice(0, -1)].join('');
    check('the old positional assembly is what failed', !verifies(leafPem, positional, rootPem));
  }

  console.log('\n4. The anchor is not sent, and does not need to be');

  {
    const presented = chain.presentationChain(leafPem, [interPem, rootPem]);
    const count = (s) => (String(s).match(/BEGIN CERTIFICATE/g) || []).length;
    // RFC 8446 §4.4.2: send the chain without the anchor. The peer either has it, in which case
    // sending it changes nothing, or it does not, in which case sending it changes nothing.
    check('leaf and intermediate only', count(presented) === 2);
    check('the root is not in the presented chain', !presented.includes(rootPem.trim()));
    check('the leaf comes first', presented.trimStart().startsWith('-----BEGIN CERTIFICATE-----'));
  }

  console.log('\n5. Anchors are extracted for the trust side');

  {
    check('the root is returned as an anchor', chain.trustAnchors([interPem, rootPem]).includes(rootPem.trim()));
    check('the intermediate is not', !chain.trustAnchors([interPem, rootPem]).includes(interPem.trim()));
    // Returning intermediates as anchors would be worse than returning nothing: it would accept
    // any chain passing through them, including one an attacker assembled.
    check('a bundle with no self-signed certificate yields nothing',
      chain.trustAnchors([interPem]) === '');
    check('an empty input yields nothing', chain.trustAnchors([]) === '' && chain.trustAnchors(null) === '');
  }

  console.log('\n6. Callers use it, so the assumption cannot come back');

  {
    const client = fs.readFileSync(path.join(__dirname, '..', 'src', 'provisioning', 'enrollment-client.js'), 'utf8');
    check('no positional slice remains', !/chainPem\.slice\(0, ?-1\)/.test(client));
    check('the enrolment path builds it semantically', /chain\.presentationChain\(issued\.certPem/.test(client));
    check('the resume path too', /chain\.presentationChain\(certPem/.test(client));

    // The OTHER half, which nothing checked and nothing used. trustAnchors() was written,
    // documented and exercised only by section 5 above -- every credential actually built
    // passed `chainPem.join('')` into Node's `ca`, which IS the trust store. An intermediate
    // in there is an anchor: path building stops at it, so the root's revocation of it is
    // never consulted, and the root CRL the IdP publishes for exactly that purpose cannot
    // reach this peer.
    check('no caller pins the whole bundle as trust anchors',
      !/ca: chainPem\.join\(''\)/.test(client));
    check('the trust store is built from anchors', /chain\.trustAnchors\(/.test(client));
    const caSites = client.match(/^\s*ca: .*$/gm) || [];
    check(`every credential's ca goes through anchorsFor (${caSites.length} sites)`,
      caSites.filter((line) => !line.includes('caPem')).every((line) => line.includes('anchorsFor(')));
  }

  console.log('\n7. A bundle with no anchor is refused, not accepted quietly');

  {
    // An empty `ca` with rejectUnauthorized does not fail closed -- Node falls back to its
    // bundled PUBLIC roots. A private PKI would start validating against the public web's
    // certificate authorities, which is worse than any of the failures above because it looks
    // like it is working.
    const { anchorsFor } = require('../src/provisioning/enrollment-client');
    if (typeof anchorsFor === 'function') {
      check('an anchored bundle resolves', anchorsFor([interPem, rootPem], 'test').includes(rootPem.trim()));
      let threw = null;
      try { anchorsFor([interPem], 'test'); } catch (e) { threw = e; }
      check('an anchorless bundle throws', threw && /nothing to anchor trust to/.test(threw.message));
      check('and says what to supply', threw && /Supply the root certificate/.test(threw.message));
    } else {
      check('anchorsFor is exported for testing', false);
    }
  }

  fs.rmSync(DIR, { recursive: true, force: true });
  console.log(`\nOK - chain assembly: ${checks} checks passed.`);
}

main();
process.exit(0);
