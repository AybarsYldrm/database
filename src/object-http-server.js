'use strict';

const http = require('node:http');

// Public objects need no key and no RBAC by construction -- "public" means anyone with the
// URL can read it, same semantics as the existing /public/* directory-serving branch already
// in grpc-server.js's _handleStream. This is that same pattern, backed by fitdb metadata
// (FitObjectStore) instead of a raw directory listing, as its own small standalone server so
// it's runnable and testable here; merging the route into an existing HTTP(S)/H2 server is a
// few lines (see the handler below, written to be embeddable).
//
// Route: GET /objects/public/<slug> -> streams the object if visibility==='public', else 404
// (private objects are NEVER reachable over plain HTTP by this server, on purpose -- they
// only exist on the capability-token-gated direct-access / gRPC path).
function createPublicObjectHandler(objectStore) {
  return async function handlePublicObjectRequest(req, res) {
    if (req.method !== 'GET') { res.writeHead(405).end('Method Not Allowed'); return; }
    const match = /^\/objects\/public\/([^/]+)$/.exec(req.url);
    if (!match) { res.writeHead(404).end('Not Found'); return; }
    const slug = decodeURIComponent(match[1]);

    let meta;
    try { meta = await objectStore.findPublicBySlug(slug); }
    catch (e) { res.writeHead(500).end('Internal Error'); return; }
    if (!meta) { res.writeHead(404).end('Object not found'); return; }

    res.writeHead(200, {
      'content-type': meta.contentType || 'application/octet-stream',
      'content-length': String(meta.size),
      'cache-control': 'public, max-age=31536000, immutable', // objectIds are content-addressed-ish (never reused), safe to cache hard
    });
    const stream = objectStore.readPublicObjectStream(meta._id);
    stream.on('error', () => { if (!res.headersSent) res.writeHead(500); res.end(); });
    stream.pipe(res);
  };
}

function createPublicObjectServer(objectStore) {
  return http.createServer(createPublicObjectHandler(objectStore));
}

module.exports = { createPublicObjectHandler, createPublicObjectServer };
