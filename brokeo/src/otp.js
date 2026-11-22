/**
 * Delivers the login OTP. Choose the channel with OTP_CHANNEL:
 *
 *   console   -> nothing is sent, the OTP is only written to the server log (local testing only)
 *   fast2sms_smart -> Fast2SMS "Smart OTP": WhatsApp first, SMS fallback (as configured in the Fast2SMS panel)
 *   fast2sms  -> SMS through Fast2SMS (https://www.fast2sms.com)
 *   whatsapp  -> WhatsApp message through Meta's Cloud API (approved Authentication template)
 *
 * fast2sms_smart env vars:
 *   FAST2SMS_API_KEY  Fast2SMS panel > Dev API > Authorization key
 *   FAST2SMS_OTP_ID   the OTP ID of the template you created in the panel's "Smart OTP" tab
 *
 * fast2sms env vars:
 *   FAST2SMS_API_KEY      Fast2SMS panel > Dev API > Authorization key
 *   FAST2SMS_ROUTE        otp (default) | q (Quick SMS) | dlt (your own DLT template)
 *   FAST2SMS_SENDER_ID    only for route=dlt
 *   FAST2SMS_TEMPLATE_ID  only for route=dlt (the message / template id shown in Fast2SMS)
 *
 * whatsapp env vars: WHATSAPP_TOKEN, WHATSAPP_PHONE_NUMBER_ID, WHATSAPP_TEMPLATE_NAME, WHATSAPP_TEMPLATE_LANG (default en_US)
 */
export const otpChannel = () => (process.env.OTP_CHANNEL || 'console').toLowerCase();

export async function sendOtp(phone, code) {
  const ch = otpChannel();
  if (ch === 'console') return console.log(`[otp -> +91${phone}] ${code}`);
  if (ch === 'fast2sms_smart') return viaFast2SmsSmart(phone, code);
  if (ch === 'fast2sms') return viaFast2Sms(phone, code);
  if (ch === 'whatsapp') return viaWhatsApp(phone, code);
  throw new Error('Unknown OTP_CHANNEL: ' + ch);
}

async function viaFast2SmsSmart(phone, code) {
  const key = process.env.FAST2SMS_API_KEY, otpId = process.env.FAST2SMS_OTP_ID;
  if (!key || !otpId) throw new Error('OTP_CHANNEL=fast2sms_smart needs FAST2SMS_API_KEY and FAST2SMS_OTP_ID');
  const res = await fetch('https://www.fast2sms.com/dev/otp/send', {
    method: 'POST',
    headers: { Authorization: key, 'Content-Type': 'application/json' },
    // We generate and check the OTP ourselves, so Fast2SMS only has to deliver the code we pass in.
    body: JSON.stringify({ mobile: phone, otp_id: otpId, otp: code, otp_expiry: 5, otp_length: 6 })
  });
  const text = await res.text();
  let j = {};
  try { j = JSON.parse(text); } catch { /* raw text is used in the error below */ }
  if (!res.ok || j.return === false) throw new Error('Fast2SMS Smart OTP error ' + res.status + ' ' + text.slice(0, 300));
}

async function viaFast2Sms(phone, code) {
  const key = process.env.FAST2SMS_API_KEY;
  if (!key) throw new Error('OTP_CHANNEL=fast2sms but FAST2SMS_API_KEY is not set');
  const route = process.env.FAST2SMS_ROUTE || 'otp';
  const body = { route, numbers: phone };
  if (route === 'otp') body.variables_values = code;                                   // delivered as "Your OTP: <code>"
  else if (route === 'q') body.message = `Your Brokeo login OTP is ${code}. It is valid for 5 minutes. Do not share it.`;
  else if (route === 'dlt') {
    if (!process.env.FAST2SMS_SENDER_ID || !process.env.FAST2SMS_TEMPLATE_ID) throw new Error('FAST2SMS_ROUTE=dlt needs FAST2SMS_SENDER_ID and FAST2SMS_TEMPLATE_ID');
    Object.assign(body, { sender_id: process.env.FAST2SMS_SENDER_ID, message: process.env.FAST2SMS_TEMPLATE_ID, variables_values: code });
  } else throw new Error('Unknown FAST2SMS_ROUTE: ' + route);

  const res = await fetch('https://www.fast2sms.com/dev/bulkV2', {
    method: 'POST',
    headers: { authorization: key, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  let j = {};
  try { j = JSON.parse(text); } catch { /* keep raw text for the error below */ }
  if (!res.ok || j.return !== true) throw new Error('Fast2SMS error ' + res.status + ' ' + text.slice(0, 300));
}

async function viaWhatsApp(phone, code) {
  const { WHATSAPP_TOKEN: token, WHATSAPP_PHONE_NUMBER_ID: id, WHATSAPP_TEMPLATE_NAME: name } = process.env;
  const lang = process.env.WHATSAPP_TEMPLATE_LANG || 'en_US';
  if (!token || !id || !name) throw new Error('WhatsApp is selected but WHATSAPP_TOKEN / WHATSAPP_PHONE_NUMBER_ID / WHATSAPP_TEMPLATE_NAME are not all set');
  const res = await fetch(`https://graph.facebook.com/v21.0/${id}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messaging_product: 'whatsapp', to: `91${phone}`, type: 'template',
      template: { name, language: { code: lang }, components: [
        { type: 'body', parameters: [{ type: 'text', text: code }] },
        { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: code }] }
      ] }
    })
  });
  if (!res.ok) throw new Error('WhatsApp API error ' + res.status + ' ' + (await res.text()).slice(0, 400));
}
