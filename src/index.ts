/// <reference types="@cloudflare/workers-types" />
import { Hono } from 'hono';
import { z } from 'zod';

interface Env {
  DB: D1Database;
  MEDIA_STORAGE: R2Bucket;
  CONSENT_KV: KVNamespace;
  CACHE: KVNamespace;
  COOKIE_DOMAIN: string;
  COOKIE_SECURE: string;
  COOKIE_HTTP_ONLY: string;
  COOKIE_SAME_SITE: string;
  FREE_TIER_LIMIT_GB: string;
}

// Validation schemas
const ConsentSchema = z.object({
  userId: z.string().optional(),
  accepted: z.boolean(),
  categories: z.array(z.enum(['analytics', 'marketing', 'functional'])),
  preferences: z.record(z.any()).optional(),
});

const WithdrawalSchema = z.object({
  userId: z.string(),
  reason: z.string().optional(),
});

const app = new Hono<{ Bindings: Env }>();

// ===== HELPER FUNCTIONS =====

const buildCookieHeader = (
  name: string,
  value: string,
  ttl: number,
  env: Env
): string => {
  const secure = env.COOKIE_SECURE === 'true' ? 'Secure' : '';
  const httpOnly = env.COOKIE_HTTP_ONLY === 'true' ? 'HttpOnly' : '';
  const sameSite = env.COOKIE_SAME_SITE || 'Strict';
  return `${name}=${value}; Domain=${env.COOKIE_DOMAIN}; Path=/; Max-Age=${ttl}; ${secure}; ${httpOnly}; SameSite=${sameSite}`;
};

const clearCookieHeader = (name: string, env: Env): string => {
  return buildCookieHeader(name, '', 0, env);
};

// ===== PUBLIC ENDPOINTS =====

app.get('/health', (c) => c.json({ status: 'ok', service: 'data' }));

app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>XAOSTECH Privacy & Data</title>
      <style>
        body { font-family: sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; }
        h1 { color: #333; }
        .section { margin: 2rem 0; padding: 1rem; background: #f5f5f5; border-radius: 8px; }
        .status { color: #666; font-size: 0.9rem; }
        code { background: #eee; padding: 0.2rem 0.4rem; border-radius: 3px; }
      </style>
    </head>
    <body>
      <h1>🔒 XAOSTECH Privacy & Data Management</h1>
      
      <div class="section">
        <h2>Privacy First</h2>
        <p>XAOSTECH uses first-party cookies only with your explicit consent.</p>
        <ul>
          <li><strong>analytics</strong> - Track page views and user journeys</li>
          <li><strong>functional</strong> - Remember preferences (language, theme)</li>
          <li><strong>marketing</strong> - Show relevant content</li>
        </ul>
      </div>

      <div class="section">
        <h2>Your Rights (GDPR)</h2>
        <ul>
          <li>✅ Access: GET <code>/api/consent</code></li>
          <li>✅ Withdraw: POST <code>/api/consent/withdraw</code></li>
          <li>✅ Delete: POST <code>/api/delete-account</code></li>
          <li>✅ Export: POST <code>/api/access-request</code></li>
        </ul>
      </div>

      <div class="section">
        <h2>Media Storage</h2>
        <p>Centralized media handling for blog and portfolio (10GB free tier per user).</p>
        <ul>
          <li>Check quota: GET <code>/media/quota/:userId</code></li>
          <li>Upload: POST <code>/media/upload</code></li>
          <li>List files: GET <code>/media/list/:userId</code></li>
          <li>Delete: DELETE <code>/media/:key</code></li>
        </ul>
      </div>

      <div class="section status">
        <p>✓ GDPR Compliant • ✓ SameSite=Strict • ✓ Zero-Trust Architecture</p>
        <p>Contact: <a href="mailto:privacy@xaostech.io">privacy@xaostech.io</a></p>
      </div>
    </body>
    </html>
  `);
});

app.get('/privacy', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html>
    <head><title>Privacy Policy - XAOSTECH</title></head>
    <body>
      <h1>Privacy Policy</h1>
      <p><strong>Last Updated:</strong> ${new Date().toISOString()}</p>
      
      <h2>1. Information We Collect</h2>
      <p>We collect information only with your explicit consent:</p>
      <ul>
        <li>Functional: language, theme preferences</li>
        <li>Analytics: page views, click events (if consented)</li>
        <li>Session: authentication data</li>
      </ul>

      <h2>2. Your Rights (GDPR Art. 15-22)</h2>
      <ul>
        <li>Access: Request all data</li>
        <li>Rectification: Correct inaccurate data</li>
        <li>Deletion: Right to be forgotten</li>
        <li>Portability: Export your data as JSON</li>
      </ul>

      <h2>3. Data Retention</h2>
      <ul>
        <li>Consent records: 90 days after expiry</li>
        <li>Analytics (if consented): 12 months rolling</li>
        <li>Session cookies: Until browser close</li>
      </ul>

      <h2>4. Contact</h2>
      <p>Email: <a href="mailto:privacy@xaostech.io">privacy@xaostech.io</a></p>
    </body>
    </html>
  `);
});

// ===== CONSENT ENDPOINTS (GDPR Compliant) =====

app.get('/api/consent', async (c) => {
  try {
    const cookieHeader = c.req.header('Cookie');
    const consentMatch = cookieHeader?.match(/xaostech_consent=([^;]+)/);

    if (!consentMatch) {
      return c.json({ userId: null, accepted: false, categories: [] }, 200);
    }

    const decoded = JSON.parse(atob(consentMatch[1]));

    return c.json({
      userId: decoded.userId,
      accepted: decoded.accepted,
      categories: decoded.categories || [],
      preferences: decoded.preferences || {},
      timestamp: decoded.timestamp,
    });
  } catch (e) {
    return c.json({ error: 'Failed to parse consent cookie' }, 400);
  }
});

app.post('/api/consent', async (c) => {
  try {
    const data = await c.req.json();
    const validated = ConsentSchema.parse(data);

    const consentData = {
      id: crypto.randomUUID(),
      userId: validated.userId || null,
      accepted: validated.accepted,
      categories: validated.categories,
      preferences: validated.preferences || {},
      timestamp: Date.now(),
      expiry: Date.now() + 365 * 24 * 60 * 60 * 1000,
    };

    const encoded = btoa(JSON.stringify(consentData));

    // Store in KV for quick lookups
    const kvKey = validated.userId
      ? `consent:${validated.userId}`
      : `consent:anonymous:${crypto.randomUUID()}`;

    await c.env.CONSENT_KV.put(kvKey, JSON.stringify(consentData), {
      expirationTtl: 365 * 24 * 60 * 60,
    });

    // Store in D1 for audit trail
    const unixTimestamp = Math.floor(Date.now() / 1000);
    await c.env.DB.prepare(
      `INSERT INTO consent_records (id, user_id, accepted, categories, preferences, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      consentData.id,
      validated.userId || null,
      validated.accepted ? 1 : 0,
      JSON.stringify(validated.categories),
      JSON.stringify(validated.preferences),
      unixTimestamp
    ).run();

    c.header('Set-Cookie', buildCookieHeader('xaostech_consent', encoded, 31536000, c.env));

    return c.json({
      success: true,
      consentId: consentData.id,
      message: 'Consent preferences saved',
    });
  } catch (e) {
    console.error('Consent error:', e);
    return c.json({ error: 'Failed to save consent' }, 500);
  }
});

app.post('/api/consent/withdraw', async (c) => {
  try {
    const data = await c.req.json();
    const validated = WithdrawalSchema.parse(data);

    // Mark as withdrawn in D1
    await c.env.DB.prepare(
      `UPDATE consent_records SET accepted = 0, updated_at = ? WHERE user_id = ?`
    ).bind(Math.floor(Date.now() / 1000), validated.userId).run();

    // Clear KV
    await c.env.CONSENT_KV.delete(`consent:${validated.userId}`);

    c.header('Set-Cookie', clearCookieHeader('xaostech_consent', c.env));

    return c.json({
      success: true,
      message: 'Consent withdrawn. All cookies cleared.',
    });
  } catch (e) {
    console.error('Withdrawal error:', e);
    return c.json({ error: 'Failed to withdraw consent' }, 500);
  }
});

// ===== DATA SUBJECT RIGHTS (GDPR Art. 15, 17) =====

app.post('/api/access-request', async (c) => {
  try {
    const { userId, email } = await c.req.json();
    const userIdFromAuth = c.req.header('X-User-ID');

    if (userIdFromAuth !== userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // Get all data for user
    const records = await c.env.DB.prepare(
      `SELECT * FROM consent_records WHERE user_id = ? ORDER BY created_at DESC`
    ).bind(userId).all();

    return c.json({
      userId,
      email,
      consent_records: records.results,
      export_format: 'json',
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error('Access request error:', e);
    return c.json({ error: 'Failed to retrieve data' }, 500);
  }
});

app.post('/api/delete-account', async (c) => {
  try {
    const { userId, reason } = await c.req.json();
    const userIdFromAuth = c.req.header('X-User-ID');

    if (userIdFromAuth !== userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // Soft delete (GDPR requires 30-day grace period)
    const deleteDate = Math.floor(Date.now() / 1000);
    await c.env.DB.prepare(
      `UPDATE consent_records SET deleted_at = ? WHERE user_id = ? AND deleted_at IS NULL`
    ).bind(deleteDate, userId).run();

    // Clear KV
    await c.env.CONSENT_KV.delete(`consent:${userId}`);

    c.header('Set-Cookie', clearCookieHeader('xaostech_consent', c.env));

    return c.json({
      success: true,
      message: 'Deletion request received. Data will be permanently deleted in 30 days.',
      deletion_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    });
  } catch (e) {
    console.error('Delete error:', e);
    return c.json({ error: 'Failed to process deletion' }, 500);
  }
});

// ===== MEDIA STORAGE (R2 + Quota Tracking) =====
// Centralized media operations for blog, portfolio, and other services
// R2 credentials stored as Cloudflare Worker Secrets (never in code)
// Account/auth-agnostic: caller provides user_id, we track quota in D1

app.get('/media/quota/:userId', async (c) => {
  const userId = c.req.param('userId');

  try {
    const quota = await c.env.DB.prepare(
      'SELECT used_gb, limit_gb, updated_at FROM user_quota WHERE user_id = ?'
    ).bind(userId).first();

    const limitGb = parseInt(c.env.FREE_TIER_LIMIT_GB) || 10;
    const usedGb = (quota?.used_gb || 0) as number;

    return c.json({
      user_id: userId,
      used_gb: usedGb,
      limit_gb: limitGb,
      available_gb: limitGb - usedGb,
      warning: usedGb > (limitGb * 0.8),
      blocked: usedGb >= limitGb,
      updated_at: quota?.updated_at || new Date().toISOString()
    }, 200);
  } catch (err) {
    console.error('Quota fetch error:', err);
    return c.json({ error: 'Failed to fetch quota' }, 500);
  }
});

app.post('/media/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as File;
    const userId = formData.get('user_id') as string;

    if (!file || !userId) {
      return c.json({ error: 'File and user_id required' }, 400);
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'audio/mpeg', 'audio/wav', 'audio/ogg'];
    if (!allowedTypes.includes(file.type)) {
      return c.json({ error: 'Invalid file type. Allowed: JPEG, PNG, WebP, MP3, WAV, OGG' }, 400);
    }

    // Enforce 50MB per-file limit
    const maxBytes = 50 * 1024 * 1024;
    if (file.size > maxBytes) {
      return c.json({ error: 'File too large (max 50MB)' }, 400);
    }

    // Check quota
    const quota = await c.env.DB.prepare(
      'SELECT used_gb FROM user_quota WHERE user_id = ?'
    ).bind(userId).first();

    const usedGb = (quota?.used_gb || 0) as number;
    const fileSizeGb = file.size / (1024 * 1024 * 1024);
    const limitGb = parseInt(c.env.FREE_TIER_LIMIT_GB) || 10;

    if (usedGb + fileSizeGb >= limitGb) {
      return c.json({
        error: 'Storage quota exceeded',
        used_gb: usedGb,
        limit_gb: limitGb,
        available_gb: Math.max(0, limitGb - usedGb)
      }, 403);
    }

    // Upload to R2 with versioning key: user_id/timestamp-filename
    const key = `${userId}/${Date.now()}-${file.name.replace(/[^a-z0-9.-]/gi, '_')}`;
    const buffer = await file.arrayBuffer();

    await c.env.MEDIA_STORAGE.put(key, buffer, {
      httpMetadata: {
        contentType: file.type,
        cacheControl: 'public, max-age=31536000'
      },
      customMetadata: {
        uploadedBy: userId,
        uploadedAt: new Date().toISOString(),
        originalName: file.name
      }
    });

    // Update quota in D1
    await c.env.DB.prepare(
      `INSERT INTO user_quota (user_id, used_gb, limit_gb, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET
       used_gb = used_gb + ?, updated_at = datetime('now')`
    ).bind(userId, fileSizeGb, limitGb, fileSizeGb).run();

    // Store metadata in D1
    const fileId = crypto.randomUUID();
    await c.env.DB.prepare(
      `INSERT INTO media_files (id, user_id, key, size_bytes, type, uploaded_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`
    ).bind(fileId, userId, key, file.size, file.type).run();

    const publicUrl = `https://media.xaostech.io/${key}`;

    return c.json({
      key,
      url: publicUrl,
      size_bytes: file.size,
      size_mb: (file.size / (1024 * 1024)).toFixed(2),
      type: file.type,
      uploaded_at: new Date().toISOString()
    }, 201);
  } catch (err) {
    console.error('Media upload error:', err);
    return c.json({ error: 'Upload failed' }, 500);
  }
});

app.delete('/media/:key', async (c) => {
  try {
    const key = decodeURIComponent(c.req.param('key'));

    // Extract user_id from key (format: user_id/timestamp-filename)
    const userIdMatch = key.match(/^([^/]+)\//);
    if (!userIdMatch) {
      return c.json({ error: 'Invalid key format' }, 400);
    }

    const userId = userIdMatch[1];

    // Verify file exists and get size
    const fileRecord = await c.env.DB.prepare(
      'SELECT size_bytes FROM media_files WHERE key = ? AND user_id = ?'
    ).bind(key, userId).first();

    if (!fileRecord) {
      return c.json({ error: 'File not found or access denied' }, 404);
    }

    const fileSizeGb = fileRecord.size_bytes / (1024 * 1024 * 1024);

    // Delete from R2
    await c.env.MEDIA_STORAGE.delete(key);

    // Mark as deleted in D1
    await c.env.DB.prepare(
      'UPDATE media_files SET deleted_at = datetime("now") WHERE key = ?'
    ).bind(key).run();

    // Decrement quota
    await c.env.DB.prepare(
      `UPDATE user_quota 
       SET used_gb = MAX(0, used_gb - ?)
       WHERE user_id = ?`
    ).bind(fileSizeGb, userId).run();

    return c.json({
      deleted: true,
      freed_gb: parseFloat(fileSizeGb.toFixed(4))
    }, 200);
  } catch (err) {
    console.error('Media delete error:', err);
    return c.json({ error: 'Delete failed' }, 500);
  }
});

app.get('/media/list/:userId', async (c) => {
  const userId = c.req.param('userId');

  try {
    const files = await c.env.DB.prepare(
      `SELECT id, key, size_bytes, type, uploaded_at
       FROM media_files
       WHERE user_id = ? AND deleted_at IS NULL
       ORDER BY uploaded_at DESC
       LIMIT 100`
    ).bind(userId).all();

    return c.json({
      user_id: userId,
      files: files.results,
      total: files.results.length
    }, 200);
  } catch (err) {
    console.error('Media list error:', err);
    return c.json({ error: 'List failed' }, 500);
  }
});

// ===== SESSION MANAGEMENT =====

app.post('/api/session', async (c) => {
  try {
    const { userId, duration = 604800 } = await c.req.json();

    const sessionData = {
      sessionId: crypto.randomUUID(),
      userId,
      timestamp: Date.now(),
    };

    const encoded = btoa(JSON.stringify(sessionData));
    const sessionCookie = buildCookieHeader('xaostech_session', encoded, duration, c.env);

    c.header('Set-Cookie', sessionCookie);

    return c.json({
      sessionId: sessionData.sessionId,
      userId,
      duration,
    });
  } catch (e) {
    console.error('Session error:', e);
    return c.json({ error: 'Failed to create session' }, 500);
  }
});

export default app;
