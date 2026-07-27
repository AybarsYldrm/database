'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');

const { requireGrpc } = require('./helpers/require-grpc');
const { GrpcClient, GRPC_STATUS } = requireGrpc();
const { createDatabaseServer } = require('../src/grpc/server');
const { createTestCaBackend, createServerIdentity, generateKeyPair } = require('./helpers/test-pki');

// Wire-compatibility check against the schema map already deployed in the IdP's
// grpc-db-adapter, reproduced here verbatim.
//
// This matters because that adapter is existing code with its own hand-written field numbers
// and no shared header file: the only thing keeping the two in sync is the wire format. If a
// field number here ever drifts from the server's, calls do not fail loudly -- protobuf skips
// unknown field numbers by design, so a renumbered field arrives as `undefined` and the
// symptom is a mysteriously empty argument, three layers away from the cause.
//
// The one change the adapter does need is transport-level, not schema-level: the data plane is
// mTLS-only now, so `rejectUnauthorized: false` with no client certificate stops being enough.

const ADAPTER_SCHEMAS = {
  DatabaseService_OpenDatabaseReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'clientSecret', type: 'string' }],
  DatabaseService_OpenDatabaseRes: [{ no: 1, name: 'message', type: 'string' }],
  DatabaseService_InsertRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'payloadJson', type: 'string' }],
  DatabaseService_InsertRecordRes: [{ no: 1, name: 'recordId', type: 'string' }],
  DatabaseService_UpdateRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'recordId', type: 'string' }, { no: 4, name: 'payloadJson', type: 'string' }],
  DatabaseService_UpdateRecordRes: [{ no: 1, name: 'message', type: 'string' }],
  DatabaseService_DeleteRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'recordId', type: 'string' }],
  DatabaseService_DeleteRecordRes: [{ no: 1, name: 'message', type: 'string' }],
  DatabaseService_FindRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'field', type: 'string' }, { no: 4, name: 'value', type: 'string' }],
  DatabaseService_FindRecordRes: [{ no: 1, name: 'payloadJson', type: 'string' }],
};

const PKG = 'custom.network';

let checks = 0;
function check(name, condition) {
  if (!condition) throw new Error(`FAILED: ${name}`);
  checks++;
  console.log(`  ok ${name}`);
}

// The adapter's own call shape, unchanged.
function invoke(client, method, reqType, resType, reqObj) {
  return client.unary(`/${PKG}.DatabaseService/${method}`, ADAPTER_SCHEMAS,
    `DatabaseService_${reqType}`, `DatabaseService_${resType}`, reqObj, { retry: { maxAttempts: 1 } });
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-adapter-compat');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const ca = createTestCaBackend();
  const serverTls = createServerIdentity(ca);
  const server = createDatabaseServer({
    baseDir,
    principals: { 'idp-service': { roles: ['admin'] } },
  });
  server.listen(0, { host: '127.0.0.1', tls: serverTls.tlsOptions });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;

  // Certificate issued directly here rather than through enrolment: this test is about the
  // schema surface, and the enrolment flow has its own suite.
  const clientKey = generateKeyPair();
  const clientCert = ca.issueDirect({
    subject: { CN: 'idp-service', O: 'fitfak' }, keyPair: clientKey, eku: ['clientAuth'],
  });

  console.log('\n[1] The adapter\'s transport settings alone are no longer sufficient');
  {
    // `{ rejectUnauthorized: false }` with no client certificate: exactly what the adapter
    // does today when no mtls block is configured.
    const legacy = new GrpcClient(target, { credentials: { rejectUnauthorized: false } });
    await assert.rejects(
      () => invoke(legacy, 'OpenDatabase', 'OpenDatabaseReq', 'OpenDatabaseRes', { dbId: '1', clientSecret: 'x' }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED,
    );
    check('a client with no certificate is refused by the data plane', true);
    legacy.close();
  }

  console.log('\n[2] With a client certificate, every adapter method works unchanged');
  const client = new GrpcClient(target, {
    // What `connectRemoteDatabase({ mtls })` already builds.
    credentials: { cert: clientCert.certPem, key: clientCert.privateKeyPem, ca: ca.ca.certPem },
  });

  // Set up a database and a collection through the full client, so the adapter's narrower
  // schema map is exercised against real data.
  const { connectDatabase } = require('../src/grpc/client');
  const handle = await connectDatabase({
    target, credentials: { cert: clientCert.certPem, key: clientCert.privateKeyPem, ca: ca.ca.certPem },
  });
  const created = await handle.createDatabase('kimlik');
  const db = await handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
  await db.defineCollection('hastalar', {
    fields: [
      { no: 2, name: 'tc', type: 'string', blindIndex: true },
      { no: 3, name: 'isim', type: 'string' },
      { no: 4, name: 'doktor', type: 'string', index: true },
      { no: 5, name: 'anamnez', type: 'string' },
    ],
  });

  {
    const opened = await invoke(client, 'OpenDatabase', 'OpenDatabaseReq', 'OpenDatabaseRes',
      { dbId: created.dbId, clientSecret: created.clientSecret });
    check('OpenDatabase returns the message field the adapter reads', typeof opened.message === 'string' && opened.message.length > 0);

    const inserted = await invoke(client, 'InsertRecord', 'InsertRecordReq', 'InsertRecordRes', {
      dbId: created.dbId, collection: 'hastalar',
      payloadJson: JSON.stringify({ tc: '11111111111', isim: 'Test Hasta', doktor: 'dr.a', anamnez: 'kontrol' }),
    });
    check('InsertRecord returns recordId', /^\d{15,}$/.test(inserted.recordId));

    // The adapter's get(id) is find('_id', id); the server special-cases that field name so
    // the adapter does not need a separate method.
    const byId = await invoke(client, 'FindRecord', 'FindRecordReq', 'FindRecordRes',
      { dbId: created.dbId, collection: 'hastalar', field: '_id', value: inserted.recordId });
    const [record] = JSON.parse(byId.payloadJson);
    check('FindRecord on _id resolves a single record', record.isim === 'Test Hasta');

    const byBlind = await invoke(client, 'FindRecord', 'FindRecordReq', 'FindRecordRes',
      { dbId: created.dbId, collection: 'hastalar', field: 'tc', value: '11111111111' });
    check('FindRecord on a blind-indexed field works', JSON.parse(byBlind.payloadJson).length === 1);

    const byPlain = await invoke(client, 'FindRecord', 'FindRecordReq', 'FindRecordRes',
      { dbId: created.dbId, collection: 'hastalar', field: 'doktor', value: 'dr.a' });
    check('FindRecord on a plain index works', JSON.parse(byPlain.payloadJson).length === 1);

    // The adapter's scan() is find('*', ''), and it must stay bounded rather than becoming an
    // unbounded decrypt of the whole collection into one response message.
    const all = await invoke(client, 'FindRecord', 'FindRecordReq', 'FindRecordRes',
      { dbId: created.dbId, collection: 'hastalar', field: '*', value: '' });
    check('FindRecord with field="*" scans the collection', JSON.parse(all.payloadJson).length === 1);

    const updated = await invoke(client, 'UpdateRecord', 'UpdateRecordReq', 'UpdateRecordRes', {
      dbId: created.dbId, collection: 'hastalar', recordId: inserted.recordId,
      payloadJson: JSON.stringify({ anamnez: 'guncellendi' }),
    });
    check('UpdateRecord returns the message field', typeof updated.message === 'string');

    const afterUpdate = await invoke(client, 'FindRecord', 'FindRecordReq', 'FindRecordRes',
      { dbId: created.dbId, collection: 'hastalar', field: '_id', value: inserted.recordId });
    const [patched] = JSON.parse(afterUpdate.payloadJson);
    check('the patch applied', patched.anamnez === 'guncellendi');
    // The adapter sends a partial object; a merge, not a replace, is what it expects.
    check('and untouched fields survive a partial update', patched.isim === 'Test Hasta');

    const deleted = await invoke(client, 'DeleteRecord', 'DeleteRecordReq', 'DeleteRecordRes',
      { dbId: created.dbId, collection: 'hastalar', recordId: inserted.recordId });
    check('DeleteRecord returns the message field', typeof deleted.message === 'string');
    check('and the record is gone', JSON.parse((await invoke(client, 'FindRecord', 'FindRecordReq', 'FindRecordRes',
      { dbId: created.dbId, collection: 'hastalar', field: '_id', value: inserted.recordId })).payloadJson).length === 0);
  }

  console.log('\n[3] Fields the adapter does not know about are simply absent');
  {
    // The server's OpenDatabaseRes carries collections/dbId/sessionExpiresAt at field numbers
    // 2-4, which the adapter's schema does not declare. proto3 skips unknown field numbers,
    // so the adapter sees only `message` -- forwards compatibility working as intended, and
    // the reason field numbers must never be reused for a different meaning.
    const opened = await invoke(client, 'OpenDatabase', 'OpenDatabaseReq', 'OpenDatabaseRes',
      { dbId: created.dbId, clientSecret: created.clientSecret });
    check('the adapter decodes only the fields it declares', Object.keys(opened).length === 1 && 'message' in opened);
  }

  client.close();
  handle.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - adapter compatibility: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
