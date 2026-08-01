'use strict';

// Classic Twitter-style Snowflake ID: 41-bit timestamp offset | 10-bit worker id | 12-bit sequence.
// Fits comfortably in a 63-bit unsigned range (safe inside an 8-byte BE buffer forever, and inside
// JS BigInt trivially). Reused across the whole fitdb stack: database ids, capability token jti,
// and default primary keys for collections that don't supply their own numeric id.
class SnowflakeGenerator {
  constructor({ workerId = 1, epoch = 1700000000000n } = {}) {
    this.workerId = BigInt(workerId) & 1023n; // 10 bits
    this.epoch = BigInt(epoch);
    this.sequence = 0n;
    this.lastTimestamp = -1n;
  }

  nextId() {
    const now = BigInt(Date.now());
    // A wall clock can step backwards -- an NTP correction, a VM restore, a manual set. The
    // previous spelling treated "not equal to the last timestamp" as "a new millisecond" and
    // reset the sequence, so after a backwards step it re-issued timestamps it had already
    // used and handed out ids it had already handed out. These ids are the primary keys of
    // every collection that does not supply its own, and a repeated key does not fail: it
    // overwrites the earlier record. Clamping to the last timestamp keeps the sequence
    // running instead, which stays unique (and monotonic) across the regression at the cost
    // of ids being very slightly ahead of the wall clock until it catches up.
    let ts = now < this.lastTimestamp ? this.lastTimestamp : now;

    if (ts === this.lastTimestamp) {
      this.sequence = (this.sequence + 1n) & 4095n; // 12 bits
      if (this.sequence === 0n) {
        // 4096 ids issued inside one millisecond. Advancing the timestamp by hand rather than
        // busy-waiting for the clock keeps this off the event loop: the loop was a spin on
        // Date.now() that blocked every other connection on the process for the rest of the
        // millisecond, and under a clock that had stepped backwards it never terminated at all.
        ts = this.lastTimestamp + 1n;
      }
    } else {
      this.sequence = 0n;
    }

    this.lastTimestamp = ts;
    return ((ts - this.epoch) << 22n) | (this.workerId << 12n) | this.sequence;
  }

  nextIdString() {
    return this.nextId().toString();
  }
}

module.exports = { SnowflakeGenerator };
