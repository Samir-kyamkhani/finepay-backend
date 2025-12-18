export default () => ({
  security: {
    jwtSecret: process.env.ACCESS_TOKEN_SECRET,
    authKeySecret: process.env.CRYPTO_SECRET_KEY,
    resetPasswordBaseUrl: process.env.RESET_PASSWORD_BASE_URL,
    production: process.env.NODE_ENV,
  },

  smtp: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT ?? '587', 10) || 587,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    fromEmail: process.env.FROM_EMAIL,
    supportEmail: process.env.SUPPORT_EMAIL,
  },

  s3: {
    region: process.env.S3_REGION,
    bucket: process.env.S3_BUCKET,
    accessKey: process.env.S3_ACCESS_KEY,
    secretKey: process.env.S3_SECRET_KEY,
  },
});
