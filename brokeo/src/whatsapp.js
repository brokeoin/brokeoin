/**
 * Sends the login OTP on WhatsApp through Meta's WhatsApp Business Cloud API.
 *
 * OTP_CHANNEL=console  -> nothing is sent, the OTP is only written to the server log (local testing only)
 * OTP_CHANNEL=whatsapp -> real WhatsApp message using an approved *Authentication* template
 *
 * Required env vars for "whatsapp":
 *   WHATSAPP_TOKEN            permanent access token of a System User (Meta Business Settings)
 *   WHATSAPP_PHONE_NUMBER_ID  the "Phone number ID" shown in the WhatsApp > API Setup page
 *   WHATSAPP_TEMPLATE_NAME    name of your approved authentication template (e.g. brokeo_login_otp)
 *   WHATSAPP_TEMPLATE_LANG    language code the template was approved in (default en_US)
 */
const GRAPH = 'https://graph.facebook.com/v21.0';

export const otpChannel = () => process.env.OTP_CHANNEL || 'console';

export async function sendWhatsAppOtp(phone, code) {
  if (otpChannel() === 'console') {
    console.log(`[otp -> whatsapp +91${phone}] ${code}`);
    return;
  }
  if (otpChannel() !== 'whatsapp') throw new Error('Unknown OTP_CHANNEL: ' + otpChannel());

  const { WHATSAPP_TOKEN: token, WHATSAPP_PHONE_NUMBER_ID: id, WHATSAPP_TEMPLATE_NAME: name } = process.env;
  const lang = process.env.WHATSAPP_TEMPLATE_LANG || 'en_US';
  if (!token || !id || !name) throw new Error('WhatsApp is selected but WHATSAPP_TOKEN / WHATSAPP_PHONE_NUMBER_ID / WHATSAPP_TEMPLATE_NAME are not all set');

  const res = await fetch(`${GRAPH}/${id}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to: `91${phone}`,
      type: 'template',
      template: {
        name,
        language: { code: lang },
        components: [
          { type: 'body', parameters: [{ type: 'text', text: code }] },
          // Authentication templates with a "Copy code" button need the code again here
          { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: code }] }
        ]
      }
    })
  });
  if (!res.ok) throw new Error('WhatsApp API error ' + res.status + ' ' + (await res.text()).slice(0, 400));
}
