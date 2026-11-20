# Brokeo (frontend + backend in one project)

- `public/index.html` is the website. It talks to the API with `fetch('/api/...')` (same origin, no CORS).
- `api/index.js` + `src/` is the Express API. On Vercel it runs as one serverless function.
- Data is stored in **Postgres** (tables are created automatically on the first request). Listing photos and KYC documents are stored in the same database (`files` table), because Vercel has no persistent disk.
- No OTP or admin password is shown on the website any more. Login is **Google sign-in**. A new Google account verifies a mobile number **once** with a WhatsApp OTP (Meta WhatsApp Business Cloud API); after that, Google sign-in alone logs the person in. OTPs are generated and checked on the server.

## Deploy on Vercel

1. Push this folder to a GitHub repo and import it in Vercel (Framework preset: **Other**; no build command).
2. Create a Postgres database: Vercel dashboard > Storage > **Neon** (free tier). It adds `DATABASE_URL` to the project for you.
3. Add these Environment Variables (Settings > Environment Variables):
   | Name | Value |
   |---|---|
   | `JWT_SECRET` | 48+ random characters: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
   | `ADMIN_PASSWORD_HASH` | output of `npm run hash-password -- "your admin password"` |
   | `GOOGLE_CLIENT_ID` | OAuth client ID (see *Google login* below) |
   | `OTP_CHANNEL` | `whatsapp` (use `console` only for private testing) |
   | `WHATSAPP_TOKEN` | permanent System User access token from Meta |
   | `WHATSAPP_PHONE_NUMBER_ID` | the *Phone number ID* from WhatsApp > API Setup |
   | `WHATSAPP_TEMPLATE_NAME` | name of your approved *Authentication* template |
   | `WHATSAPP_TEMPLATE_LANG` | language the template was approved in, e.g. `en_US` |
4. Deploy. Open `https://your-project.vercel.app` (owner/agent login) and `/#admin` (verification desk).

### Google login
1. Google Cloud Console > APIs & Services > **OAuth consent screen**: set app name, support email, and publish the app (status *In production*) so anyone can sign in.
2. **Credentials > Create credentials > OAuth client ID > Web application**.
3. *Authorized JavaScript origins*: `https://brokeo.in`, `https://www.brokeo.in`, your `https://<project>.vercel.app` URL, and `http://localhost:3000` for local testing. No redirect URI is needed.
4. Copy the client ID into `GOOGLE_CLIENT_ID`.

### WhatsApp OTP (Meta Cloud API)
1. developers.facebook.com > create an app (type *Business*) > add the **WhatsApp** product, and connect a Meta Business account.
2. Add a business phone number (it cannot be one that is already registered on the normal WhatsApp app) and note its **Phone number ID**.
3. WhatsApp Manager > Message templates > create a template with category **Authentication** (it comes with a *Copy code* button). Wait for approval, then put its name and language in the env vars.
4. Business Settings > Users > **System users**: create one, assign the WhatsApp app, generate a token with `whatsapp_business_messaging` permission, never expiring. That is `WHATSAPP_TOKEN`.
5. Complete business verification in Meta Business Suite and move the app to *Live* mode, otherwise messages only reach test numbers.

### How login works
- Google account already linked: Google sign-in logs in straight away.
- New Google account: Google sign-in, then the person enters a mobile number, receives a 6-digit OTP on WhatsApp, and the Google account is linked to that number permanently (table `identities`). Owners and agents are separate: one Google account can be linked once as owner and once as agent.
- A mobile number can be linked to only one Google account per role.
- People who used the old mobile-number login keep their data: they sign in with Google, verify the same number once, and are linked to the existing account.
- Agent approval/rejection no longer sends a message; agents see their status when they log in.

## Run locally
```bash
npm install
cp .env.example .env     # fill in DATABASE_URL, JWT_SECRET, ADMIN_PASSWORD_HASH, GOOGLE_CLIENT_ID
npm start                # http://localhost:3000 (with OTP_CHANNEL=console the WhatsApp OTP appears in this terminal)
```

## Limits to know about
- Vercel rejects request bodies over 4.5 MB. The site compresses photos and KYC scans in the browser, so normal use stays well under this.
- Rate limits are counted per server instance (serverless), so they are a soft guard. OTP attempt limits and cooldowns are stored in the database and are exact.
- PAN numbers are stored as plain text and KYC images are stored unencrypted in Postgres. Get advice on India's DPDP Act before collecting real KYC data.
- Not run end to end in the sandbox where this was assembled (no network to install packages). Test each role once after deploying: owner, agent (submit KYC), admin (approve), agent again.
