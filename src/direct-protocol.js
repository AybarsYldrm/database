'use strict';

// v2 wire format (breaking change from v1: adds requestId for multiplexing -- no deployed
// client existed against v1, so this is a clean replacement rather than a versioned one).
//
// Request:  [opCode:1][requestId:4 BE][tokenLen:2 BE][token][dbIdLen:1][dbId][collLen:1][coll][argsLen:4 BE][args]
// Response: [requestId:4 BE][bodyLen:4 BE][body]
//
// A client may keep a single TCP/TLS socket open and have several requests in flight at
// once; the server does not guarantee responding in request order (whichever operation
// finishes first writes first), so `requestId` is how a client matches a response back to
// the request that produced it. `args`/`body` are JSON deliberately -- this is a thin
// control-plane RPC channel, not the storage hot path (that's binary+encrypted end to end
// in storage-engine.js).
//
// TCP is a byte stream: a single 'data' event is not guaranteed to contain exactly one
// frame, or even one whole frame, and a single connection now carries many frames over its
// lifetime rather than exactly one. Every reader below accumulates chunks and only fires
// once a complete frame is available, and keeps whatever partial bytes remain for the next
// event -- this now matters even more than in the one-shot v1 protocol.

function bigintSafeReplacer(_key, value) { return typeof value === 'bigint' ? value.toString() : value; }
function toJsonSafe(obj) { return JSON.stringify(obj, bigintSafeReplacer); }

function buildRequestFrame({ opCode, requestId, token, dbId, collection = '', args = {} }) {
  const tokenBuf = Buffer.from(token, 'utf8');
  const dbIdBuf = Buffer.from(String(dbId), 'utf8');
  const collectionBuf = Buffer.from(collection, 'utf8');
  const argsBuf = Buffer.from(toJsonSafe(args), 'utf8');
  if (tokenBuf.length > 0xffff) throw new Error('fitdb: capability token too large for direct-protocol frame');
  if (dbIdBuf.length > 0xff) throw new Error('fitdb: dbId too large for direct-protocol frame');
  if (collectionBuf.length > 0xff) throw new Error('fitdb: collection name too large for direct-protocol frame');

  const requestIdBuf = Buffer.alloc(4); requestIdBuf.writeUInt32BE(requestId >>> 0, 0);
  const tokenLenBuf = Buffer.alloc(2); tokenLenBuf.writeUInt16BE(tokenBuf.length, 0);
  const argsLenBuf = Buffer.alloc(4); argsLenBuf.writeUInt32BE(argsBuf.length, 0);

  return Buffer.concat([
    Buffer.from([opCode]), requestIdBuf,
    tokenLenBuf, tokenBuf,
    Buffer.from([dbIdBuf.length]), dbIdBuf,
    Buffer.from([collectionBuf.length]), collectionBuf,
    argsLenBuf, argsBuf,
  ]);
}

function parseRequestFrame(frame) {
  let o = 0;
  const opCode = frame.readUInt8(o); o += 1;
  const requestId = frame.readUInt32BE(o); o += 4;
  const tokenLen = frame.readUInt16BE(o); o += 2;
  const token = frame.subarray(o, o + tokenLen).toString('utf8'); o += tokenLen;
  const dbIdLen = frame.readUInt8(o); o += 1;
  const dbId = frame.subarray(o, o + dbIdLen).toString('utf8'); o += dbIdLen;
  const collectionLen = frame.readUInt8(o); o += 1;
  const collection = frame.subarray(o, o + collectionLen).toString('utf8'); o += collectionLen;
  const argsLen = frame.readUInt32BE(o); o += 4;
  const argsBuf = frame.subarray(o, o + argsLen);
  const args = argsBuf.length ? JSON.parse(argsBuf.toString('utf8')) : {};
  return { opCode, requestId, token, dbId, collection, args };
}

function buildResponseFrame(requestId, obj) {
  const body = Buffer.from(toJsonSafe(obj), 'utf8');
  const reqIdBuf = Buffer.alloc(4); reqIdBuf.writeUInt32BE(requestId >>> 0, 0);
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32BE(body.length, 0);
  return Buffer.concat([reqIdBuf, lenBuf, body]);
}

function parseResponseFrame(frame) {
  const requestId = frame.readUInt32BE(0);
  const len = frame.readUInt32BE(4);
  const body = JSON.parse(frame.subarray(8, 8 + len).toString('utf8'));
  return { requestId, body };
}

function createFrameReader(onFrame) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (buf.length < 7) return; // opCode(1) + requestId(4) + tokenLen(2)
      const tokenLen = buf.readUInt16BE(5);
      const afterToken = 7 + tokenLen;
      if (buf.length < afterToken + 1) return;
      const dbIdLen = buf.readUInt8(afterToken);
      const afterDbId = afterToken + 1 + dbIdLen;
      if (buf.length < afterDbId + 1) return;
      const collectionLen = buf.readUInt8(afterDbId);
      const afterCollection = afterDbId + 1 + collectionLen;
      if (buf.length < afterCollection + 4) return;
      const argsLen = buf.readUInt32BE(afterCollection);
      const frameLen = afterCollection + 4 + argsLen;
      if (buf.length < frameLen) return;
      const frame = buf.subarray(0, frameLen);
      buf = buf.subarray(frameLen);
      onFrame(frame);
    }
  };
}

function createResponseFrameReader(onFrame) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (buf.length < 8) return; // requestId(4) + bodyLen(4)
      const len = buf.readUInt32BE(4);
      const frameLen = 8 + len;
      if (buf.length < frameLen) return;
      const frame = buf.subarray(0, frameLen);
      buf = buf.subarray(frameLen);
      onFrame(frame);
    }
  };
}

module.exports = {
  buildRequestFrame, parseRequestFrame, buildResponseFrame, parseResponseFrame,
  createFrameReader, createResponseFrameReader,
};
