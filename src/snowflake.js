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
    let ts = BigInt(Date.now());
    if (ts === this.lastTimestamp) {
      this.sequence = (this.sequence + 1n) & 4095n; // 12 bits
      if (this.sequence === 0n) {
        // sequence exhausted within the same millisecond, spin until clock advances
        while (ts <= this.lastTimestamp) ts = BigInt(Date.now());
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
