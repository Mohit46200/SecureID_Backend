import { read, write } from '../utils/store.js';
import {
  hashOtp,
  makeOtp,
  challengeExpiry,
  newId,
} from '../utils/security.js';

const testOtpCache = new Map();

export async function createChallenge({
  userId,
  channel,
  destination,
  purpose = 'verification',
}) {
  const otp = makeOtp();
  const challenges = await read('challenges');

  const challenge = {
    challengeId: newId(),
    userId,
    channel,
    destination,
    purpose,
    otpHash: hashOtp(otp),
    expiresAt: challengeExpiry(),
    attempts: 0,
    maxAttempts: 3,
    used: false,
    createdAt: new Date().toISOString(),
  };

  challenges.push(challenge);
  await write('challenges', challenges);

  testOtpCache.set(challenge.challengeId, {
    otp,
    createdAt: Date.now(),
  });

  console.log('');
  console.log(`[SIMULATED ${channel.toUpperCase()}]`);
  console.log(`To: ${destination}`);
  console.log(`OTP: ${otp}`);
  console.log(`Challenge: ${challenge.challengeId}`);
  console.log('');

  return challenge;
}

export async function verifyChallenge(
  challengeId,
  otp,
) {
  const challenges = await read('challenges');
  const challenge = challenges.find(
    (item) => item.challengeId === challengeId,
  );

  if (!challenge) {
    return {
      ok: false,
      message: 'Challenge not found.',
    };
  }

  if (challenge.used) {
    return {
      ok: false,
      message: 'This code has already been used.',
    };
  }

  if (new Date(challenge.expiresAt) < new Date()) {
    return {
      ok: false,
      message: 'Code expired.',
    };
  }

  if (challenge.attempts >= challenge.maxAttempts) {
    return {
      ok: false,
      message:
        'Maximum attempts reached. Request a new code.',
    };
  }

  challenge.attempts += 1;

  if (challenge.otpHash !== hashOtp(otp)) {
    await write('challenges', challenges);

    return {
      ok: false,
      message: `Incorrect code. Please try again. You have ${Math.max(
        0,
        challenge.maxAttempts - challenge.attempts,
      )} attempts left.`,
    };
  }

  challenge.used = true;
  challenge.verifiedAt = new Date().toISOString();

  await write('challenges', challenges);

  return {
    ok: true,
    challenge,
  };
}

export function getTestOtp(challengeId) {
  const item = testOtpCache.get(challengeId);

  if (!item) {
    return null;
  }

  if (Date.now() - item.createdAt > 10 * 60 * 1000) {
    testOtpCache.delete(challengeId);
    return null;
  }

  return item.otp;
}

export async function latestChallenge(
  userId,
  channel,
  purpose,
) {
  const challenges = await read('challenges');

  return [...challenges]
    .reverse()
    .find(
      (challenge) =>
        challenge.userId === userId &&
        challenge.channel === channel &&
        challenge.purpose === purpose &&
        !challenge.used,
    );
}
