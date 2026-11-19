/** Sends an SMS. "console" logs it on the server (local testing only). "twilio" sends for real. */
export async function sendSms(phone, text) {
  const provider = process.env.SMS_PROVIDER || 'console';
  if (provider === 'console') {
    console.log(`[sms -> +91${phone}] ${text}`);
    return;
  }
  if (provider === 'twilio') {
    const { TWILIO_ACCOUNT_SID: sid, TWILIO_AUTH_TOKEN: token, TWILIO_FROM: from } = process.env;
    if (!sid || !token || !from) throw new Error('Twilio is selected but TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM are not all set');
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${sid}:${token}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ To: `+91${phone}`, From: from, Body: text })
    });
    if (!res.ok) throw new Error('SMS provider error ' + res.status + ' ' + (await res.text()).slice(0, 300));
    return;
  }
  // To use another gateway (MSG91, Gupshup, Fast2SMS...) add a branch here.
  // Indian operators require DLT-registered sender IDs and templates for transactional SMS.
  throw new Error('Unknown SMS_PROVIDER: ' + provider);
}
