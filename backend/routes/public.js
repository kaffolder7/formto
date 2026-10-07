import crypto from 'crypto';
import sql, { dbHelpers } from '../utils/db.js';
import { emailHelpers } from '../utils/mailer.js';
import { sendSlackNotification } from '../utils/slack.js';
import { getRequestIp } from '../middleware/rateLimit.js';
import { validateWebhookUrl } from '../utils/validation.js';
import { sendPinnedWebhookRequest } from '../utils/webhookHttp.js';
import { renderHostedForm } from '../utils/hostedForm.js';
import { authorizeSubmission, allowPublicOrigin, saveWithQuota } from '../utils/submissionPolicy.js';
import { readiness, SubmissionError } from '../utils/submissionSecurity.js';
import { sendTelegramNotification } from '../utils/telegram.js';

function isBlockedByList(blocklist = [], data = {}, ip = '') {
  for (const entry of blocklist) {
    if (!entry?.type || !entry?.value) continue;
    const v = String(entry.value).toLowerCase();
    if (entry.type === 'ip' && ip === v) return true;
    if (entry.type === 'email') {
      const emailVal = Object.values(data).find(val => String(val).toLowerCase() === v);
      if (emailVal) return true;
    }
    if (entry.type === 'domain') {
      const domainMatch = Object.values(data).some(val => {
        const s = String(val).toLowerCase();
        return s.endsWith(`@${v}`) || s === v;
      });
      if (domainMatch) return true;
    }
  }
  return false;
}

async function deliverWebhook(form, submissionData, metadata) {
  const urls = [form.webhook_url, form.slack_webhook_url, form.discord_webhook_url].filter(Boolean);

  for (const url of urls) {
    try {
      const validation = await validateWebhookUrl(url);
      if (!validation.valid) continue;

      const payload = {
        event: 'form.submission',
        form: { id: form.id, name: form.name, endpoint: form.endpoint },
        submission: { data: submissionData, metadata, timestamp: new Date().toISOString() }
      };

      await sendPinnedWebhookRequest(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'FormTo-Webhook/1.0',
          'X-FormTo-Event': 'form.submission',
          'X-FormTo-Signature': crypto.createHmac('sha256', process.env.JWT_SECRET || 'secret').update(JSON.stringify(payload)).digest('hex')
        },
        body: JSON.stringify(payload),
        timeoutMs: 8000
      });

      // Log webhook delivery
      await sql`
        INSERT INTO webhook_logs (form_id, payload, status)
        VALUES (${form.id}, ${sql.json(payload)}, 'success')
      `;
    } catch (err) {
      console.error('[Webhook] Delivery failed');
      try {
        await sql`
          INSERT INTO webhook_logs (form_id, payload, status)
          VALUES (${form.id}, ${sql.json({ url, error: err.message })}, 'failed')
        `;
      } catch {}
    }
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

export default async function publicRoutes(fastify, options = {}) {
  function failure(error, request, reply) {
    if (error instanceof SubmissionError) {
      request.log?.info({ category: error.code }, 'Submission rejected');
      if (error.retryAfter) reply.header('Retry-After', error.retryAfter);
      return reply.status(error.status).send({ error: error.code, message: error.message });
    }
    if (error.statusCode >= 400 && error.statusCode < 500) {
      request.log?.info({ category: 'invalid_request' }, 'Submission rejected');
      return reply.status(error.statusCode).send({ error: 'invalid_request', message: 'Check the request format and size, then try again.' });
    }
    request.log?.error({ category: 'submission_error' }, 'Submission failed');
    return reply.status(500).send({ error: 'Internal server error', message: 'Please try again later' });
  }

  // Parser errors occur before the route handler and need the same safe logging.
  fastify.setErrorHandler(failure);

  fastify.options('/f/:endpoint', async (request, reply) => {
    const form = await dbHelpers.getFormByEndpoint(request.params.endpoint);
    if (!form || !['public', 'legacy'].includes(form.submission_mode)) return reply.status(404).send();
    try {
      if (form.submission_mode === 'legacy') reply.header('Access-Control-Allow-Origin', '*');
      else allowPublicOrigin(form, request, reply);
      return reply.header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        .header('Access-Control-Allow-Headers', 'Content-Type, Accept').status(204).send();
    } catch (error) { return failure(error, request, reply); }
  });
  // GET /f/:endpoint — render hosted form
  fastify.get('/f/:endpoint', async (request, reply) => {
    const { endpoint } = request.params;
    const form = await dbHelpers.getFormByEndpoint(endpoint);

    if (!form || !['public', 'legacy'].includes(form.submission_mode) || !form.hosted_enabled) return reply.status(404).send({ error: 'Form not found' });
    if (!form.active || readiness(form)) {
      return reply.status(200).type('text/html').send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;"><h2>This form is no longer accepting submissions.</h2></body></html>`);
    }

    if (form.close_at && new Date(form.close_at) < new Date()) {
      return reply.status(200).type('text/html').send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;"><h2>This form is closed.</h2></body></html>`);
    }

    return reply.type('text/html').send(renderHostedForm(form));
  });

  // POST /f/:endpoint — receive submission
  fastify.post('/f/:endpoint', async (request, reply) => {
    const { endpoint } = request.params;
    const ip = getRequestIp(request);

    try {
      const form = await dbHelpers.getFormByEndpoint(endpoint);

      if (!form) {
        return reply.status(404).send({ error: 'Form not found', message: 'No form found with this endpoint' });
      }

      const submissionData = await authorizeSubmission(form, request, reply, options.verifyTurnstile);
      if (submissionData === null) return reply.status(200).send({ success: true });

      // Check blocklist
      if (Array.isArray(form.blocklist) && form.blocklist.length > 0) {
        if (isBlockedByList(form.blocklist, submissionData, ip)) {
          // Silent accept (don't tell bots they're blocked)
          return reply.status(200).send({ success: true });
        }
      }

      // Build metadata
      const metadata = {
        ip,
        userAgent: request.headers['user-agent'] || '',
        referer: request.headers.referer || request.headers.referrer || '',
        timestamp: new Date().toISOString()
      };

      // Save submission
      let notify;
      try {
        ({ notify } = await saveWithQuota(form, submissionData, metadata));
      } catch (err) {
        if (err.message?.includes('FORM_SUBMISSION_LIMIT_REACHED')) {
          return reply.status(422).send({ error: 'Form closed', message: 'This form has reached its submission limit' });
        }
        throw err;
      }

      if (notify) {
        const formName = form.name || form.endpoint;

        // Email notification
        // Per-form notification_email overrides the account-level owner_notify_email
        const emailRecipient = form.notification_email || form.owner_notify_email;
        if (form.notify_email && emailRecipient) {
          emailHelpers.sendSubmissionNotification({
            ...form,
            notification_emails: [emailRecipient],
            _smtpConfig: form.owner_smtp_config
          }, submissionData).catch(err => {
            console.error('[Email] Notification failed');
          });
        }

        // Telegram notification
        if (form.notify_telegram && form.owner_telegram_bot_token && form.owner_telegram_chat_id) {
          sendTelegramNotification(form.owner_telegram_bot_token, form.owner_telegram_chat_id, {
            formName,
            submissionData
          }).catch(err => {
            console.error('[Telegram] Notification failed');
          });
        }

        // Slack notification
        if (form.notify_slack && form.owner_slack_webhook_url) {
          sendSlackNotification(form.owner_slack_webhook_url, {
            formName,
            submissionData
          }).catch(err => {
            console.error('[Slack] Notification failed');
          });
        }

        // Deliver webhooks (fire and forget)
        if (form.webhook_url || form.slack_webhook_url || form.discord_webhook_url) {
          deliverWebhook(form, submissionData, metadata).catch(err => {
            console.error('[Webhook] Delivery error');
          });
        }

      }

      // Redirect or respond
      const acceptsHtml = request.headers.accept?.includes('text/html');
      if (form.redirect_url && acceptsHtml) {
        return reply.redirect(302, form.redirect_url);
      }

      return reply.status(200).send({ success: true });
    } catch (err) {
      return failure(err, request, reply);
    }
  });
}
