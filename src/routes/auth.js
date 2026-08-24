import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { read, write } from '../utils/store.js';
import { newId } from '../utils/security.js';
import {
  createChallenge,
  verifyChallenge,
  getTestOtp,
} from '../services/otpService.js';
import { requireJwt, requireSession } from '../middleware.js';

const router = express.Router();

const safeUser = (user) => ({
  id: user.id,
  fullName: user.fullName,
  email: user.email,
  phone: user.phone,
  emailVerified: user.emailVerified,
  mobileVerified: user.mobileVerified,
});

const findUser = async (identifier) => {
  const users = await read('users');
  const value = String(identifier || '').toLowerCase();

  return {
    users,
    user: users.find(
      (user) =>
        user.email.toLowerCase() === value ||
        user.username?.toLowerCase() === value,
    ),
  };
};

const findUserById = async (id) => {
  const users = await read('users');

  return {
    users,
    user: users.find((user) => user.id === id),
  };
};

router.post('/register', async (req, res) => {
  const {
    fullName,
    email,
    phone,
    password,
    agree,
  } = req.body;

  if (!fullName || !email || !phone || !password || !agree) {
    return res.status(400).json({
      message: 'Please complete all required fields.',
    });
  }

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({
      message: 'Enter a valid email address.',
    });
  }

  if (
    password.length < 8 ||
    !/[A-Z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !/[\W_]/.test(password)
  ) {
    return res.status(400).json({
      message: 'Password does not meet the required rules.',
    });
  }

  const { users, user } = await findUser(email);

  if (user) {
    return res.status(409).json({
      message: 'An account with this email already exists.',
    });
  }

  const newUser = {
    id: newId(),
    fullName,
    email: email.toLowerCase(),
    phone,
    passwordHash: await bcrypt.hash(password, 12),
    emailVerified: false,
    mobileVerified: false,
    failedLoginAttempts: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);
  await write('users', users);

  const challenge = await createChallenge({
    userId: newUser.id,
    channel: 'email',
    destination: newUser.email,
    purpose: 'registration-email',
  });

  return res.status(201).json({
    challengeId: challenge.challengeId,
    destination: newUser.email,
  });
});

router.post('/send-email-otp', async (req, res) => {
  const { challengeId } = req.body;
  const challenges = await read('challenges');
  const oldChallenge = challenges.find(
    (challenge) => challenge.challengeId === challengeId,
  );

  if (!oldChallenge) {
    return res.status(404).json({
      message: 'Challenge not found.',
    });
  }

  const challenge = await createChallenge({
    userId: oldChallenge.userId,
    channel: 'email',
    destination: oldChallenge.destination,
    purpose: oldChallenge.purpose,
  });

  return res.json({
    challengeId: challenge.challengeId,
    destination: challenge.destination,
  });
});

router.post('/verify-email-otp', async (req, res) => {
  const result = await verifyChallenge(
    req.body.challengeId,
    req.body.otp,
  );

  if (!result.ok) {
    return res.status(400).json({
      message: result.message,
    });
  }

  const users = await read('users');
  const user = users.find(
    (item) => item.id === result.challenge.userId,
  );

  if (!user) {
    return res.status(404).json({
      message: 'User not found.',
    });
  }

  user.emailVerified = true;
  await write('users', users);

  const challenge = await createChallenge({
    userId: user.id,
    channel: 'sms',
    destination: user.phone,
    purpose: 'registration-sms',
  });

  return res.json({
    challengeId: challenge.challengeId,
    destination: user.phone,
  });
});

router.post('/send-sms-otp', async (req, res) => {
  const { challengeId } = req.body;
  const challenges = await read('challenges');
  const oldChallenge = challenges.find(
    (challenge) => challenge.challengeId === challengeId,
  );

  if (!oldChallenge) {
    return res.status(404).json({
      message: 'Challenge not found.',
    });
  }

  const users = await read('users');
  const user = users.find((item) => item.id === oldChallenge.userId);

  if (!user) {
    return res.status(404).json({
      message: 'User not found.',
    });
  }

  const destination = oldChallenge.purpose === 'login'
    ? user.phone
    : oldChallenge.destination;

  const challenge = await createChallenge({
    userId: oldChallenge.userId,
    channel: 'sms',
    destination,
    purpose: oldChallenge.purpose,
  });

  return res.json({
    challengeId: challenge.challengeId,
    destination: challenge.destination,
  });
});

router.post('/verify-sms-otp', async (req, res) => {
  const result = await verifyChallenge(
    req.body.challengeId,
    req.body.otp,
  );

  if (!result.ok) {
    return res.status(400).json({
      message: result.message,
    });
  }

  const users = await read('users');
  const user = users.find(
    (item) => item.id === result.challenge.userId,
  );

  if (!user) {
    return res.status(404).json({
      message: 'User not found.',
    });
  }

  user.mobileVerified = true;
  await write('users', users);

  return res.json({
    message: 'Mobile verified.',
  });
});

router.post('/login', async (req, res) => {
  const {
    identifier,
    password,
  } = req.body;

  const { users, user } = await findUser(identifier);

  if (!user) {
    return res.status(401).json({
      message: 'Invalid email or password. Please try again.',
    });
  }

  if (
    user.lockedUntil &&
    new Date(user.lockedUntil) > new Date()
  ) {
    return res.status(423).json({
      message: 'Account temporarily locked. Please try again later.',
    });
  }

  const validPassword = await bcrypt.compare(
    password || '',
    user.passwordHash,
  );

  if (!validPassword) {
    user.failedLoginAttempts =
      (user.failedLoginAttempts || 0) + 1;

    if (user.failedLoginAttempts >= 5) {
      user.lockedUntil = new Date(
        Date.now() + 5 * 60 * 1000,
      ).toISOString();
      user.failedLoginAttempts = 0;
    }

    await write('users', users);

    return res.status(401).json({
      message: 'Invalid email or password. Please try again.',
    });
  }

  user.failedLoginAttempts = 0;

  await write('users', users);

  const challenge = await createChallenge({
    userId: user.id,
    channel: 'email',
    destination: user.email,
    purpose: 'login',
  });

  return res.json({
    verificationRequired: true,
    method: 'email',
    challengeId: challenge.challengeId,
    destination: challenge.destination,
  });
});

router.post('/verify-login-otp', async (req, res) => {
  const result = await verifyChallenge(
    req.body.challengeId,
    req.body.otp,
  );

  if (!result.ok) {
    return res.status(400).json({
      message: result.message,
    });
  }

  if (result.challenge.purpose !== 'login') {
    return res.status(400).json({
      message: 'Invalid login verification challenge.',
    });
  }

  const users = await read('users');
  const user = users.find(
    (item) => item.id === result.challenge.userId,
  );

  if (!user) {
    return res.status(404).json({
      message: 'User not found.',
    });
  }

  req.session.userId = user.id;
  req.session.verified = true;

  return res.json({
    authenticated: true,
    user: safeUser(user),
  });
});

router.get('/me', requireSession, async (req, res) => {
  const { user } = await findUserById(req.session.userId);

  if (!user) {
    return res.status(404).json({
      message: 'User not found.',
    });
  }

  return res.json({
    user: safeUser(user),
  });
});

router.post('/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        message: 'Could not log out.',
      });
    }

    res.clearCookie('connect.sid');

    return res.json({
      message: 'Logged out.',
    });
  });
});

router.post('/token', async (req, res) => {
  let user = null;

  // Preferred flow: the user has already completed login + OTP
  // and has an authenticated server-side session.
  if (req.session?.userId) {
    const result = await findUserById(req.session.userId);
    user = result.user;
  }

  // Keep the endpoint independently usable for the assignment's
  // separate JWT authentication demonstration.
  if (!user) {
    const { identifier, password } = req.body || {};
    const result = await findUser(identifier);

    if (
      result.user &&
      (await bcrypt.compare(
        password || '',
        result.user.passwordHash,
      ))
    ) {
      user = result.user;
    }
  }

  if (!user) {
    return res.status(401).json({
      message: 'Authenticated session or valid credentials required.',
    });
  }

  const token = jwt.sign(
    {
      sub: user.id,
      email: user.email,
      fullName: user.fullName,
    },
    process.env.JWT_SECRET || 'dev-jwt-secret',
    {
      expiresIn: '10m',
    },
  );

  return res.json({
    token,
    tokenType: 'Bearer',
    expiresIn: 600,
    issuedAt: new Date().toISOString(),
  });
});

router.get('/protected', requireJwt, async (req, res) => {
  return res.json({
    message: 'JWT protected resource reached.',
    subject: req.jwtUser.sub,
  });
});

router.get('/test/otp', async (req, res) => {
  try {
    const { challengeId } = req.query;

    if (!challengeId) {
      return res.status(400).json({
        message: 'challengeId is required.',
      });
    }

    const challenges = await read('challenges');

    const challenge = challenges.find(
      (item) => item.challengeId === challengeId,
    );

    if (!challenge) {
      return res.status(404).json({
        message: 'Challenge not found.',
      });
    }

    const otp = getTestOtp(challenge.challengeId);

    if (!otp) {
      return res.status(404).json({
        message: 'OTP not available for this challenge.',
      });
    }

    return res.json({
      success: true,
      otp,
      channel: challenge.channel,
      destination: challenge.destination,
      challengeId: challenge.challengeId,
      expiresAt: challenge.expiresAt,
    });
  } catch (error) {
    console.error(
      'Test OTP endpoint error:',
      error,
    );

    return res.status(500).json({
      message: 'Unable to retrieve test OTP.',
    });
  }
});

export default router;
