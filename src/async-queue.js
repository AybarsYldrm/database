'use strict';

// Serializes async operations against a shared resource (one collection's active segment
// file/index state) so concurrent insert()/update()/delete() calls can never interleave
// their append+index-mutation steps. A failure in one queued task must not stall the
// tasks queued after it, so the internal tail always settles regardless of outcome while
// each caller still receives the real (possibly rejected) promise for their own task.
class AsyncQueue {
  constructor() { this._tail = Promise.resolve(); }

  run(fn) {
    const result = this._tail.then(() => fn());
    this._tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

module.exports = { AsyncQueue };
