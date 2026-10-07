import sql from '../utils/db.js';
import {
  validateEmailTemplate,
  validateFormEndpoint,
  validateHostedFields,
  validateWebhookUrl
} from '../utils/validation.js';
import {
  normalizeEmailConfig,
  normalizeEmailList,
  normalizeSingleEmail
} from '../utils/emailSecurity.js';
import { emailHelpers, replaceVariables, sanitizeTemplate, generateDefaultEmailTemplate } from '../utils/mailer.js';
import validator from 'validator';

import { SECURITY_COLUMNS, securityUpdates } from '../utils/formSecuritySettings.js';
import { publicForm, newCredential, readiness } from '../utils/submissionSecurity.js';

const INTERNAL_ERROR_MESSAGE = 'Please try again later.';

const SAFE_FORM_COLS = [
  'id', 'user_id', 'name', 'endpoint', 'description', 'tags',
  'active', 'created_at', 'updated_at', 'submission_count', 'logo_url',
  'notification_email', 'notification_emails', 'notification_type', 'redirect_url',
  'email_config', 'email_template_enabled', 'email_template_subject', 'email_template_body',
  'webhook_url', 'slack_webhook_url', 'discord_webhook_url',
  'notify_email', 'notify_telegram', 'notify_slack',
  'blocklist', 'close_after_submissions', 'close_at', ...SECURITY_COLUMNS
].join(', ');

const ALLOWED_UPDATE_FIELDS = new Set([
  'name', 'description', 'active', 'redirect_url',
  'notification_email', 'notification_emails', 'notification_type',
  'webhook_url', 'slack_webhook_url', 'discord_webhook_url',
  'notify_email', 'notify_telegram', 'notify_slack',
  'email_config', 'email_template_enabled', 'email_template_subject', 'email_template_body',
  'logo_url',
  'blocklist', 'close_after_submissions', 'close_at', 'tags'
]);

function pickAllowed(payload = {}) {
  return Object.entries(payload).reduce((acc, [k, v]) => {
    if (ALLOWED_UPDATE_FIELDS.has(k)) acc[k] = v;
    return acc;
  }, {});
}

function normalizeEmailSettings(updates = {}) {
  const out = { ...updates };

  if ('notification_email' in out) {
    const r = normalizeSingleEmail(out.notification_email, { fieldName: 'notification email', allowEmpty: true });
    if (!r.valid) return r;
    out.notification_email = r.normalized;
  }
  if ('notification_emails' in out) {
    const r = normalizeEmailList(out.notification_emails, { fieldName: 'notification_emails', allowEmpty: true });
    if (!r.valid) return r;
    out.notification_emails = r.normalized;
  }
  if ('email_config' in out) {
    const r = normalizeEmailConfig(out.email_config, { allowEmpty: true });
    if (!r.valid) return r;
    out.email_config = r.normalized;
  }

  return { valid: true, normalized: out };
}

export default async function formRoutes(fastify) {
  // GET /api/forms — list user's forms
  fastify.get('/', { preHandler: fastify.auth }, async (request, reply) => {
    try {
      const forms = await sql`
        SELECT id, user_id, name, endpoint, description, tags, active,
               created_at, submission_count, logo_url, submission_mode, hosted_enabled, security_configured
        FROM forms
        WHERE user_id = ${request.user.userId}
        ORDER BY created_at DESC
      `;
      return { forms };
    } catch (err) {
      console.error('Error fetching forms:', err);
      return reply.status(500).send({ error: 'Failed to fetch forms', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // GET /api/forms/:formId
  fastify.get('/:formId', { preHandler: fastify.auth }, async (request, reply) => {
    try {
      const [form] = await sql.unsafe(
        `SELECT ${SAFE_FORM_COLS} FROM forms WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [request.params.formId, request.user.userId]
      );
      if (!form) return reply.status(404).send({ error: 'Form not found' });
      const [usage] = await sql`SELECT submissions, notifications FROM form_daily_usage
        WHERE form_id = ${form.id} AND day = (NOW() AT TIME ZONE 'UTC')::date`;
      return { form: { ...publicForm(form), usage_today: usage || { submissions: 0, notifications: 0 } } };
    } catch (err) {
      console.error('Error fetching form:', err);
      return reply.status(500).send({ error: 'Failed to fetch form', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // GET /api/forms/:formId/stats
  fastify.get('/:formId/stats', { preHandler: fastify.auth }, async (request, reply) => {
    try {
      const { formId } = request.params;
      const [form] = await sql`SELECT id FROM forms WHERE id = ${formId} AND user_id = ${request.user.userId}`;
      if (!form) return reply.status(404).send({ error: 'Form not found' });

      const [stats] = await sql`
        SELECT
          COUNT(*) FILTER (WHERE archived = false)                                                          AS total,
          COUNT(*) FILTER (WHERE archived = false AND read_at IS NULL)                                      AS unread,
          COUNT(*) FILTER (WHERE archived = true)                                                           AS archived,
          COUNT(*) FILTER (WHERE archived = false AND created_at >= date_trunc('week', NOW()))              AS this_week,
          COUNT(*) FILTER (WHERE archived = false AND created_at >= date_trunc('day', NOW()))               AS today
        FROM submissions
        WHERE form_id = ${formId}
      `;
      return { stats };
    } catch (err) {
      console.error('Error fetching form stats:', err);
      return reply.status(500).send({ error: 'Failed to fetch stats', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // POST /api/forms — create form
  fastify.post('/', { preHandler: fastify.auth }, async (request, reply) => {
    try {
      const {
        name, endpoint, description,
        notification_email, redirect_url, email_config,
        webhook_url, slack_webhook_url, discord_webhook_url,
        active = false
      } = request.body || {};

      if (!name || !endpoint) {
        return reply.status(400).send({ error: 'name and endpoint are required' });
      }

      const epVal = validateFormEndpoint(endpoint);
      if (!epVal.valid) return reply.status(400).send({ error: 'Invalid endpoint', message: epVal.error });

      const normalizedEndpoint = epVal.normalizedValue;

      const emailSettings = normalizeEmailSettings({ notification_email, email_config });
      if (!emailSettings.valid) return reply.status(400).send({ error: 'Invalid email settings', message: emailSettings.error });

      if (redirect_url) {
        try {
          const u = new URL(redirect_url);
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            return reply.status(400).send({ error: 'Invalid redirect_url', message: 'Redirect URL must use http or https' });
          }
        } catch {
          return reply.status(400).send({ error: 'Invalid redirect_url', message: 'Redirect URL must be a valid URL' });
        }
      }

      for (const [field, value] of [['webhook_url', webhook_url], ['slack_webhook_url', slack_webhook_url], ['discord_webhook_url', discord_webhook_url]]) {
        if (!value) continue;
        const v = await validateWebhookUrl(value, { requireHttps: true });
        if (!v.valid) return reply.status(400).send({ error: `Invalid ${field}`, message: v.error });
      }

      const fieldsVal = validateHostedFields(request.body.fields);
      if (!fieldsVal.valid) return reply.status(400).send({ error: 'Invalid form fields', message: fieldsVal.error });

      const tmplVal = validateEmailTemplate(request.body);
      if (!tmplVal.valid) return reply.status(400).send({ error: 'Invalid email template', message: tmplVal.error });

      const [existing] = await sql`SELECT id FROM forms WHERE endpoint = ${normalizedEndpoint} LIMIT 1`;
      if (existing) return reply.status(409).send({ error: 'Endpoint already in use' });

      let security;
      try { security = securityUpdates(request.body || {}); }
      catch (error) { return reply.status(400).send({ error: 'Invalid security settings', message: error.message }); }
      const values = {
        user_id: request.user.userId, name, endpoint: normalizedEndpoint,
        description: description || null,
        notification_email: emailSettings.normalized.notification_email || null,
        redirect_url: redirect_url || null,
        email_config: emailSettings.normalized.email_config ? sql.json(emailSettings.normalized.email_config) : null,
        webhook_url: webhook_url || null, slack_webhook_url: slack_webhook_url || null,
        discord_webhook_url: discord_webhook_url || null, active: !!active, ...security,
      };
      for (const key of ['fields', 'allowed_origins']) values[key] = sql.json(values[key]);
      const [form] = await sql`INSERT INTO forms ${sql(values)} RETURNING ${sql.unsafe(SAFE_FORM_COLS)}`;

      return reply.status(201).send({ form: publicForm(form) });
    } catch (err) {
      console.error('Error creating form:', err);
      return reply.status(500).send({ error: 'Failed to create form', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // PUT /api/forms/:formId — update form
  fastify.put('/:formId', { preHandler: fastify.auth }, async (request, reply) => {
    try {
      const { formId } = request.params;
      const updates = pickAllowed(request.body || {});

      const [existing] = await sql`SELECT * FROM forms WHERE id = ${formId} AND user_id = ${request.user.userId}`;
      if (!existing) return reply.status(404).send({ error: 'Form not found' });

      try { Object.assign(updates, securityUpdates(request.body || {}, existing)); }
      catch (error) { return reply.status(400).send({ error: 'Invalid security settings', message: error.message }); }

      if (Object.keys(updates).length === 0) {
        return reply.status(400).send({ error: 'No valid fields to update' });
      }

      const emailSettings = normalizeEmailSettings(updates);
      if (!emailSettings.valid) return reply.status(400).send({ error: 'Invalid email settings', message: emailSettings.error });
      Object.assign(updates, emailSettings.normalized);

      if (updates.redirect_url) {
        try {
          const u = new URL(updates.redirect_url);
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            return reply.status(400).send({ error: 'Invalid redirect_url', message: 'Redirect URL must use http or https' });
          }
        } catch {
          return reply.status(400).send({ error: 'Invalid redirect_url', message: 'Redirect URL must be a valid URL' });
        }
      }

      for (const [field, value] of [['webhook_url', updates.webhook_url], ['slack_webhook_url', updates.slack_webhook_url], ['discord_webhook_url', updates.discord_webhook_url]]) {
        if (!value) continue;
        const v = await validateWebhookUrl(value, { requireHttps: true });
        if (!v.valid) return reply.status(400).send({ error: `Invalid ${field}`, message: v.error });
      }

      const tmplVal = validateEmailTemplate(updates);
      if (!tmplVal.valid) return reply.status(400).send({ error: 'Invalid email template', message: tmplVal.error });

      updates.updated_at = new Date();
      updates.security_revision = existing.security_revision + 1;
      for (const key of ['allowed_origins', 'fields', 'tags', 'blocklist', 'notification_emails', 'email_config']) {
        if (updates[key] !== undefined && updates[key] !== null) updates[key] = sql.json(updates[key]);
      }

      const keys = Object.keys(updates);
      const setClauses = keys.map((k, i) => `${k} = $${i + 3}`).join(', ');
      const values = [formId, request.user.userId, ...Object.values(updates)];

      const [form] = await sql.unsafe(
        `UPDATE forms SET ${setClauses} WHERE id = $1 AND user_id = $2 AND security_revision = ${existing.security_revision} RETURNING ${SAFE_FORM_COLS}`,
        values
      );

      if (!form) return reply.status(409).send({ error: 'Settings changed', message: 'Reload settings and try again' });
      return { form: publicForm(form) };
    } catch (err) {
      console.error('Error updating form:', err);
      return reply.status(500).send({ error: 'Failed to update form', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // DELETE /api/forms/:formId
  fastify.delete('/:formId', { preHandler: [fastify.auth, fastify.rateLimitSensitive] }, async (request, reply) => {
    try {
      const { formId } = request.params;
      const result = await sql`DELETE FROM forms WHERE id = ${formId} AND user_id = ${request.user.userId} RETURNING id`;
      if (!result.length) return reply.status(404).send({ error: 'Form not found' });
      return { success: true };
    } catch (err) {
      console.error('Error deleting form:', err);
      return reply.status(500).send({ error: 'Failed to delete form', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // PATCH /api/forms/:formId/toggle
  fastify.patch('/:formId/toggle', { preHandler: fastify.auth }, async (request, reply) => {
    try {
      const { formId } = request.params;
      const [existing] = await sql`SELECT * FROM forms WHERE id = ${formId} AND user_id = ${request.user.userId}`;
      if (!existing) return reply.status(404).send({ error: 'Form not found' });
      const issue = readiness(existing);
      if (!existing.active && issue) return reply.status(400).send({ error: 'Setup required', message: issue });
      const [form] = await sql`UPDATE forms SET active = ${!existing.active}, security_revision = security_revision + 1,
        updated_at = NOW() WHERE id = ${formId} AND user_id = ${request.user.userId}
        AND security_revision = ${existing.security_revision} RETURNING id, active`;
      if (!form) return reply.status(409).send({ error: 'Settings changed. Reload and try again.' });
      return { form };
    } catch (err) {
      console.error('Error toggling form:', err);
      return reply.status(500).send({ error: 'Failed to toggle form', message: INTERNAL_ERROR_MESSAGE });
    }
  });

  // Owner-only, write-once credentials; never reuse account authentication tokens.
  fastify.post('/:formId/submission-key', { preHandler: [fastify.auth, fastify.rateLimitSensitive] }, async (request, reply) => {
    const key = newCredential();
    const [form] = await sql`UPDATE forms SET submission_key_hash = ${key.hash}, submission_key_prefix = ${key.prefix},
      submission_key_created_at = NOW(), security_revision = security_revision + 1
      WHERE id = ${request.params.formId} AND user_id = ${request.user.userId} AND submission_mode = 'private'
      RETURNING id, submission_key_prefix, submission_key_created_at`;
    if (!form) return reply.status(404).send({ error: 'Private form not found' });
    reply.header('Cache-Control', 'no-store');
    return reply.status(201).send({ token: key.token, ...form });
  });
  fastify.delete('/:formId/submission-key', { preHandler: [fastify.auth, fastify.rateLimitSensitive] }, async (request, reply) => {
    const [form] = await sql`UPDATE forms SET submission_key_hash = NULL, submission_key_prefix = NULL,
      submission_key_created_at = NULL, active = false, security_revision = security_revision + 1
      WHERE id = ${request.params.formId} AND user_id = ${request.user.userId} AND submission_mode = 'private' RETURNING id`;
    if (!form) return reply.status(404).send({ error: 'Form not found' });
    return { success: true };
  });

  // POST /api/forms/:formId/test-email
  fastify.post('/:formId/test-email', {
    preHandler: [fastify.auth, fastify.rateLimitSensitive]
  }, async (request, reply) => {
    try {
      const { formId } = request.params;
      const { email } = request.body || {};

      if (!email || !validator.isEmail(email)) {
        return reply.status(400).send({ error: 'Invalid email address' });
      }

      const [form] = await sql.unsafe(
        `SELECT id, name, email_template_enabled, email_template_subject, email_template_body, logo_url FROM forms WHERE id = $1 AND user_id = $2`,
        [formId, request.user.userId]
      );
      if (!form) return reply.status(404).send({ error: 'Form not found' });

      const [owner] = await sql`SELECT smtp_config FROM users WHERE id = ${request.user.userId}`;
      const smtpConfig = owner?.smtp_config || null;

      const sampleData = {
        name: 'John Doe', email: 'john@example.com',
        message: 'This is a sample form submission.',
        phone: '+1 (555) 123-4567'
      };

      let validatedLogoUrl = '';
      if (form.logo_url) {
        try {
          const u = new URL(form.logo_url);
          if (u.protocol === 'http:' || u.protocol === 'https:') validatedLogoUrl = form.logo_url;
        } catch {}
      }

      const vars = {
        form_name: form.name,
        date: new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }),
        time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        datetime: new Date().toLocaleString('en-US', { month: 'long', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }),
        logo: validatedLogoUrl,
        ...sampleData
      };

      let subject, htmlBody;
      if (form.email_template_enabled && form.email_template_body) {
        subject = replaceVariables(form.email_template_subject || 'New submission from {{form_name}}', vars);
        let tmpl = sanitizeTemplate(form.email_template_body);
        tmpl = validatedLogoUrl
          ? tmpl.replace(/\{\{#if logo\}\}([\s\S]*?)\{\{\/if\}\}/g, '$1')
          : tmpl.replace(/\{\{#if logo\}\}[\s\S]*?\{\{\/if\}\}/g, '');
        htmlBody = replaceVariables(tmpl, vars);
      } else {
        subject = `New submission from ${form.name}`;
        htmlBody = generateDefaultEmailTemplate(form.name, sampleData);
      }

      await emailHelpers.sendEmail({
        smtpConfig,
        to: email,
        subject: `[TEST] ${subject}`,
        html: `<div style="background:#fef3c7;border:1px solid #f59e0b;padding:12px;margin-bottom:20px;border-radius:4px;"><strong>⚠️ This is a test email</strong></div>${htmlBody}`
      });

      return { success: true };
    } catch (err) {
      console.error('Test email error:', err);
      return reply.status(500).send({ error: 'Failed to send test email', message: INTERNAL_ERROR_MESSAGE });
    }
  });
}
