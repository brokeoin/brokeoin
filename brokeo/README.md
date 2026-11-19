# Brokeo (frontend + backend in one project)

- `public/index.html` is the website. It talks to the API with `fetch('/api/...')` (same origin, no CORS).
- `api/index.js` + `src/` is the Express API. On Vercel it runs as one serverless function.
- Data is stored in **Postgres** (tables are created automatically on the first request). Listing photos and KYC documents are stored in the same database (`files` table), because Vercel has no persistent disk.
- No OTP or admin password is shown on the website any more. OTPs are generated and checked on the server and sent by SMS.

## Deploy on Vercel

1. Push this folder to a GitHub repo and import it in Vercel (Framework preset: **Other**; no build command).
2. Create a Postgres database: Vercel dashboard > Storage > **Neon** (free tier). It adds `DATABASE_URL` to the project for you.
3. Add these Environment Variables (Settings > Environment Variables):
   | Name | Value |
   |---|---|
   | `JWT_SECRET` | 48+ random characters: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
   | `ADMIN_PASSWORD_HASH` | output of `npm run hash-password -- "your admin password"` |
   | `SMS_PROVIDER` | `twilio` |
   | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` | from your Twilio account |
4. Deploy. Open `https://your-project.vercel.app` (owner/agent login) and `/#admin` (verification desk).

### About SMS
Real SMS needs a provider. For India, sender IDs and message templates must be DLT-registered; to use MSG91, Fast2SMS, etc., add a branch in `src/sms.js`.
With `SMS_PROVIDER=console` nothing is sent: the OTP is only written to the server log (Vercel > Logs). Use that only for private testing.

## Run locally
```bash
npm install
cp .env.example .env     # fill in DATABASE_URL, JWT_SECRET, ADMIN_PASSWORD_HASH
npm start                # http://localhost:3000 (OTP appears in this terminal)
```

## Limits to know about
- Vercel rejects request bodies over 4.5 MB. The site compresses photos and KYC scans in the browser, so normal use stays well under this.
- Rate limits are counted per server instance (serverless), so they are a soft guard. OTP attempt limits and cooldowns are stored in the database and are exact.
- PAN numbers are stored as plain text and KYC images are stored unencrypted in Postgres. Get advice on India's DPDP Act before collecting real KYC data.
- Not run end to end in the sandbox where this was assembled (no network to install packages). Test each role once after deploying: owner, agent (submit KYC), admin (approve), agent again.
