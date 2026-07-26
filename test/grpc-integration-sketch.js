'use strict';

// ILLUSTRATIVE ONLY -- this file is not executed by any test in this project (it references
// `app`, `PERMISSIONS`, `GRPC_STATUS`, `verifyAuthToken` etc. from your existing server.js,
// which owns graph-store.js/reflection.js internals not part of this deliverable). It shows
// the shape of wiring fitdb into your CURRENT gRPC layer as an additional controller,
// side-by-side with AuthService/ObjectStoreService, ahead of whatever eventually replaces
// the gRPC transport itself.
//
// Nothing about fitdb depends on gRPC, or on this shape -- lib/direct-server.js is a
// completely separate, capability-token-authenticated transport for exactly the
// "skip the edge round-trip" case described in the brief. This file only covers the
// EDGE-MEDIATED path: normal RBAC-gated requests that go through the existing gateway.
//
// -----------------------------------------------------------------------------------------
// const { DatabaseManager, DB_PERMISSIONS, CapabilityKeyRing, CapabilityTokenService, SnowflakeGenerator } = require('../lib');
//
// const dbManager = new DatabaseManager({ baseDir: './fitdb-data' });
// const capabilityKeys = new CapabilityKeyRing();
// const capabilityTokens = new CapabilityTokenService(capabilityKeys, new SnowflakeGenerator({ workerId: 3 }));
//
// app.registerController('DatabaseService', {
//
//   CreateDatabase: {
//     requiresAuth: true,
//     requiredPermissions: PERMISSIONS.WRITE_DATA, // existing edge-level RBAC gate
//     request: [{ no: 1, name: 'name', type: 'string' }],
//     response: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'clientSecret', type: 'string' }],
//     handler: async (req, call) => {
//       const { dbId, clientSecret } = await dbManager.createDatabase({ ownerId: call.user.id, name: req.name });
//       // clientSecret crosses the wire exactly once, over TLS, straight to the owner -- it
//       // is never written to any log or persisted server-side beyond this response.
//       return { dbId, clientSecret };
//     },
//   },
//
//   // A capability grant: the edge server has already verified the caller's JWT + RBAC, and
//   // is now handing out a narrow, short-lived, single-use token that the client can present
//   // DIRECTLY to lib/direct-server.js -- bypassing this gateway entirely for that one
//   // operation. This is the "gecici hmac + kid" flow from the brief.
//   IssueCapability: {
//     requiresAuth: true,
//     requiredPermissions: PERMISSIONS.READ_DATA,
//     request: [
//       { no: 1, name: 'dbId', type: 'string' },
//       { no: 2, name: 'collection', type: 'string' },
//       { no: 3, name: 'scope', type: 'int32' },     // must be a subset of the caller's own DB_PERMISSIONS mask
//       { no: 4, name: 'ttlMs', type: 'int32' },
//     ],
//     response: [{ no: 1, name: 'token', type: 'string' }],
//     handler: async (req, call) => {
//       const db = dbManager.getOpenDatabase(req.dbId);
//       if (!db || !db.acl.can(call.user.id, req.scope)) {
//         const err = new Error('Bu veritabanı için bu yetki kapsamına sahip değilsiniz.');
//         err.code = GRPC_STATUS.PERMISSION_DENIED; throw err;
//       }
//       const token = capabilityTokens.issue({
//         sub: call.user.id, dbId: req.dbId, collection: req.collection,
//         scope: req.scope, ttlMs: Math.min(req.ttlMs || 30000, 120000), singleUse: true,
//       });
//       return { token };
//     },
//   },
//
// });
//
// -----------------------------------------------------------------------------------------
// Client side then has two ways to reach the same data:
//   1) Edge-mediated (existing pattern): callGrpcMethod('/custom.network.DatabaseService/...')
//   2) Direct: request a capability via IssueCapability once, then talk straight to
//      lib/direct-server.js's TCP/TLS listener for however many operations that capability
//      authorizes -- see examples/direct-access-demo.js for the wire-level client code.
