import crypto from 'crypto';
import { randomUUID } from 'crypto';

export function newId() {
  return randomUUID();
}

export function makeOtp() {
  return String(
    crypto.randomInt(100000, 1000000),
  );
}

export function hashOtp(otp) {
  return crypto
    .createHash('sha256')
    .update(String(otp))
    .digest('hex');
}

export function challengeExpiry() {
  return new Date(
    Date.now() + 3 * 60 * 1000,
  ).toISOString();
}
