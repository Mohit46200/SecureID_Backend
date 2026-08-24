import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import session from 'express-session';
import authRoutes from './routes/auth.js';

const app = express();
const PORT = process.env.PORT || 5000;

const allowedOrigins = (
  process.env.FRONTEND_ORIGIN ||
  'http://localhost:5173',
  "https://secure-id-ebon.vercel.app"
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error('Origin not allowed by CORS.'));
    },
    credentials: true,
  }),
);

app.use(express.json());

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      'dev-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite:
        process.env.NODE_ENV === 'production'
          ? 'none'
          : 'lax',
      maxAge: 1000 * 60 * 60 * 2,
    },
  }),
);

app.get('/api/health', (req, res) => {
  return res.json({
    ok: true,
    service: 'SecureID API',
    authFlow: 'email-sms-only',
  });
});

app.use('/api', authRoutes);

app.use((error, req, res, next) => {
  console.error(error);

  return res.status(500).json({
    message: 'Internal server error.',
  });
});

app.listen(PORT, () => {
  console.log(
    `SecureID API running on http://localhost:${PORT}`,
  );
});
