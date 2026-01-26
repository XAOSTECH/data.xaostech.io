/// <reference types="@cloudflare/workers-types" />
import { Hono } from 'hono';
import { z } from 'zod';

interface Env {
  DB: D1Database;
  ACCOUNT_DB: D1Database;
  BLOG_DB: D1Database;
  CHAT_DB: D1Database;
  IMG: R2Bucket;
  BLOG_MEDIA: R2Bucket;
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

import { getSecurityHeaders } from '../shared/types/security';

const app = new Hono<{ Bindings: Env }>();

// Global security headers middleware
// For binary responses (R2 streams), we add headers directly instead of re-wrapping
// the Response, which can cause stream consumption issues
app.use('*', async (c, next) => {
  await next();

  const res = c.res;
  if (!res) return;

  // Get content-type to check if binary
  const contentType = res.headers.get('content-type') || '';
  const isBinary = contentType.startsWith('image/') ||
    contentType.startsWith('audio/') ||
    contentType.startsWith('video/') ||
    contentType.startsWith('application/octet-stream');

  // For binary responses, add security headers to existing response
  // without re-wrapping (avoids stream consumption issues)
  const secHeaders = getSecurityHeaders();
  if (isBinary) {
    for (const k of Object.keys(secHeaders)) {
      res.headers.set(k, secHeaders[k]);
    }
    return res;
  }

  // For other responses, create new response with security headers
  const headers = new Headers(res.headers);
  for (const k of Object.keys(secHeaders)) {
    headers.set(k, secHeaders[k]);
  }

  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
});

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
        <p>XAOSTECH uses first-party cookies only.</p>
        <ul>
          <li><strong>functional</strong> - Account management, authorisation, cache and preferences</li>
          <li><strong><s>analytics</s></strong> - None + Cloudflare webbeacon disabled</li>
          <li><strong><s>marketing</s></strong> - None; not interested.</li>
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

// ===== FAVICON =====
app.get('/favicon.ico', async (c) => {
  try {
    const object = await c.env.IMG.get('XAOSTECH_LOGO.png');
    if (!object) return c.notFound();

    const headers = new Headers();
    headers.set('Content-Type', 'image/png');
    headers.set('Cache-Control', 'public, max-age=604800');

    return new Response(object.body, { status: 200, headers });
  } catch (err) {
    console.error('[DATA] favicon serve error:', err);
    return c.json({ error: 'Failed to serve favicon' }, 500);
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

    await c.env.IMG.put(key, buffer, {
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
    await c.env.IMG.delete(key);

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

// ===== ASSET SERVING (Favicons, logos from IMG bucket) =====

app.get('/assets/:filename', async (c) => {
  const filename = c.req.param('filename');

  if (!filename) {
    return c.json({ error: 'Filename required' }, 400);
  }

  try {
    const traceId = c.req.header('X-Trace-Id') || null;
    const incomingHasCfAccessClientId = !!(c.req.header('CF-Access-Client-Id') || c.req.header('Cf-Access-Client-Id'));
    const incomingHasCfAccessJwt = !!(c.req.header('cf-access-jwt-assertion') || c.req.header('CF-Access-JWT-Assertion'));
    const imgBindingPresent = !!(c.env && c.env.IMG);

    console.debug('[DATA] Incoming asset request presence:', { traceId, incomingHasCfAccessClientId, incomingHasCfAccessJwt, imgBindingPresent, path: c.req.path });

    // Try to read object; catch and log any IMG.get error specifically
    let object: any;
    try {
      object = await c.env.IMG.get(filename);
    } catch (imgErr: any) {
      console.error('[DATA] IMG.get threw an error', { traceId, filename, err: imgErr?.message || String(imgErr), stack: imgErr?.stack || undefined });
      return c.json({ error: 'Failed to read asset from IMG', traceId }, 500);
    }

    if (!object) {
      console.warn('[DATA] Asset not found', { traceId, filename });
      return c.json({ error: 'Asset not found', traceId }, 404);
    }

    // Return the object with proper headers
    const headers = new Headers();
    try {
      object.writeHttpMetadata(headers);
    } catch (metaErr: any) {
      console.error('[DATA] Failed to write object metadata', { traceId, filename, err: metaErr?.message || String(metaErr) });
    }

    // Ensure content-type is set (fallback based on extension if R2 didn't provide it)
    if (!headers.get('content-type')) {
      const ext = filename.split('.').pop()?.toLowerCase() || '';
      const mimeTypes: Record<string, string> = {
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'ico': 'image/x-icon',
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'mp4': 'video/mp4',
        'webm': 'video/webm',
        'pdf': 'application/pdf',
      };
      headers.set('Content-Type', mimeTypes[ext] || 'application/octet-stream');
    }

    headers.set('Cache-Control', 'public, max-age=604800'); // 1 week cache
    // Echo trace id for easier correlation
    if (traceId) headers.set('X-Trace-Id', traceId);

    console.debug('[DATA] Returning asset', { traceId, filename });
    return new Response(object.body, {
      status: 200,
      headers
    });
  } catch (err: any) {
    console.error('[DATA] Error fetching asset general handler error', { filename, err: err?.message || String(err), stack: err?.stack || undefined });
    return c.json({ error: 'Failed to fetch asset', traceId: c.req.header('X-Trace-Id') || null }, 500);
  }
});

// ===== BLOG MEDIA ENDPOINTS (R2) =====

app.post('/blog-media/upload', async (c) => {
  const userId = c.req.header('X-User-ID');

  if (!userId) {
    return c.json({ error: 'User ID required' }, 401);
  }

  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as File;
    const bucket = formData.get('bucket') as string || 'blog-media';

    if (!file) {
      return c.json({ error: 'No file provided' }, 400);
    }

    // Determine which R2 bucket to use
    let r2Bucket: R2Bucket;
    if (bucket === 'blog-media') {
      r2Bucket = c.env.BLOG_MEDIA;
    } else {
      return c.json({ error: 'Invalid bucket' }, 400);
    }

    // Upload to R2
    const r2Key = `${userId}/${Date.now()}-${file.name.replace(/[^a-z0-9.-]/gi, '_')}`;
    const buffer = await file.arrayBuffer();

    await r2Bucket.put(r2Key, buffer, {
      httpMetadata: {
        contentType: file.type,
      },
      customMetadata: {
        uploadedBy: userId,
        uploadedAt: new Date().toISOString(),
      },
    });

    // Return metadata for caller to record
    return c.json({
      mediaId: crypto.randomUUID(),
      r2_key: r2Key,
      url: `https://${bucket}.xaostech.io/${r2Key}`,
      bucket,
      size: file.size,
    }, 201);
  } catch (err: any) {
    console.error('Blog media upload error:', err);
    return c.json({ error: 'Upload failed' }, 500);
  }
});

app.get('/blog-media/:key', async (c) => {
  const key = c.req.param('key');

  if (!key) {
    return c.json({ error: 'Key required' }, 400);
  }

  try {
    const object = await c.env.BLOG_MEDIA.get(key);

    if (!object) {
      return c.json({ error: 'Media not found' }, 404);
    }

    // Return the object with proper headers
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('Cache-Control', 'public, max-age=31536000');

    return new Response(object.body, {
      status: 200,
      headers
    });
  } catch (err: any) {
    console.error('Error fetching blog media:', err);
    return c.json({ error: 'Failed to fetch media' }, 500);
  }
});

// =============================================================================
// USER AUTH ROUTES (for API worker to call via service binding)
// Uses ACCOUNT_DB for user storage
// =============================================================================

// Find user by GitHub ID
app.get('/users/github/:githubId', async (c) => {
  const githubId = c.req.param('githubId');
  const db = c.env.ACCOUNT_DB;

  if (!db) {
    return c.json({ error: 'ACCOUNT_DB not configured' }, 501);
  }

  try {
    const row = await db.prepare(`
      SELECT id, username, email, avatar_url, role, is_admin, github_id, github_username, github_avatar_url
      FROM users WHERE github_id = ?
    `).bind(githubId).first();

    if (!row) {
      return c.json({ found: false }, 200);
    }

    return c.json({ found: true, user: row });
  } catch (err: any) {
    console.error('User lookup error:', err);
    return c.json({ error: 'Database error' }, 500);
  }
});

// Find user by email (for email/password auth)
app.get('/users/email/:email', async (c) => {
  const email = decodeURIComponent(c.req.param('email'));
  const db = c.env.ACCOUNT_DB;

  if (!db) {
    return c.json({ error: 'ACCOUNT_DB not configured' }, 501);
  }

  try {
    const row = await db.prepare(`
      SELECT id, username, email, avatar_url, role, is_admin, password_hash
      FROM users WHERE email = ?
    `).bind(email).first();

    if (!row) {
      return c.json({ found: false }, 200);
    }

    return c.json({ found: true, user: row });
  } catch (err: any) {
    console.error('User email lookup error:', err);
    return c.json({ error: 'Database error' }, 500);
  }
});

// Get user by ID
app.get('/users/:userId', async (c) => {
  const userId = c.req.param('userId');
  const db = c.env.ACCOUNT_DB;

  if (!db) {
    return c.json({ error: 'ACCOUNT_DB not configured' }, 501);
  }

  try {
    const row = await db.prepare(`
      SELECT id, username, email, avatar_url, role, is_admin, github_id, created_at
      FROM users WHERE id = ?
    `).bind(userId).first();

    if (!row) {
      return c.json({ error: 'User not found' }, 404);
    }

    return c.json({ user: row });
  } catch (err: any) {
    console.error('User fetch error:', err);
    return c.json({ error: 'Database error' }, 500);
  }
});

// Create new user (GitHub OAuth signup or email/password registration)
app.post('/users', async (c) => {
  const db = c.env.ACCOUNT_DB;

  if (!db) {
    return c.json({ error: 'ACCOUNT_DB not configured' }, 501);
  }

  try {
    const body = await c.req.json();
    const { id, github_id, username, email, avatar_url, github_username, github_avatar_url, role, password_hash } = body;

    // Support both OAuth and password-based registration
    if (password_hash) {
      // Email/password registration
      await db.prepare(`
        INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(id, username, email, password_hash, role || 'user').run();
    } else {
      // GitHub OAuth registration
      await db.prepare(`
        INSERT INTO users (id, github_id, username, email, avatar_url, github_username, github_avatar_url, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(id, github_id, username, email, avatar_url, github_username || '', github_avatar_url || '', role || 'user').run();
    }

    return c.json({ success: true, userId: id }, 201);
  } catch (err: any) {
    console.error('User create error:', err);
    return c.json({ error: 'Failed to create user', details: err.message }, 500);
  }
});

// Update user (login tracking, profile updates)
app.patch('/users/:userId', async (c) => {
  const userId = c.req.param('userId');
  const db = c.env.ACCOUNT_DB;

  if (!db) {
    return c.json({ error: 'ACCOUNT_DB not configured' }, 501);
  }

  try {
    const body = await c.req.json();
    const updates: string[] = [];
    const values: any[] = [];

    // Only update provided fields
    if (body.github_username !== undefined) {
      updates.push('github_username = ?');
      values.push(body.github_username);
    }
    if (body.github_avatar_url !== undefined) {
      updates.push('github_avatar_url = ?');
      values.push(body.github_avatar_url);
    }
    if (body.username !== undefined) {
      updates.push('username = ?');
      values.push(body.username);
    }
    if (body.avatar_url !== undefined) {
      updates.push('avatar_url = ?');
      values.push(body.avatar_url);
    }
    if (body.email !== undefined) {
      updates.push('email = ?');
      values.push(body.email);
    }
    if (body.last_login !== undefined) {
      updates.push('updated_at = datetime("now")');
    }

    if (updates.length === 0) {
      return c.json({ error: 'No fields to update' }, 400);
    }

    values.push(userId);
    await db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();

    return c.json({ success: true });
  } catch (err: any) {
    console.error('User update error:', err);
    return c.json({ error: 'Failed to update user' }, 500);
  }
});

// =============================================================================
// BLOG ROUTES (for API worker to call via service binding)
// Uses BLOG_DB for posts storage
// =============================================================================

// List published posts
app.get('/blog/posts', async (c) => {
  const db = c.env.BLOG_DB;

  if (!db) {
    return c.json({ error: 'BLOG_DB not configured' }, 501);
  }

  try {
    const { results } = await db.prepare(`
      SELECT id, slug, title, excerpt, author_id, created_at, published_at, status
      FROM posts 
      WHERE status = 'published' 
      ORDER BY published_at DESC 
      LIMIT 100
    `).all();

    return c.json({ posts: results });
  } catch (err: any) {
    console.error('Blog posts list error:', err);
    return c.json({ error: 'Failed to fetch posts' }, 500);
  }
});

// Get single post by ID or slug
app.get('/blog/posts/:idOrSlug', async (c) => {
  const idOrSlug = c.req.param('idOrSlug');
  const db = c.env.BLOG_DB;

  if (!db) {
    return c.json({ error: 'BLOG_DB not configured' }, 501);
  }

  try {
    // Try by ID first, then by slug
    let row = await db.prepare(`
      SELECT id, slug, title, content, excerpt, author_id, created_at, published_at, status, featured_image_url
      FROM posts WHERE id = ?
    `).bind(idOrSlug).first();

    if (!row) {
      row = await db.prepare(`
        SELECT id, slug, title, content, excerpt, author_id, created_at, published_at, status, featured_image_url
        FROM posts WHERE slug = ?
      `).bind(idOrSlug).first();
    }

    if (!row) {
      return c.json({ error: 'Post not found' }, 404);
    }

    return c.json({ post: row });
  } catch (err: any) {
    console.error('Blog post fetch error:', err);
    return c.json({ error: 'Failed to fetch post' }, 500);
  }
});

// Create new post
app.post('/blog/posts', async (c) => {
  const db = c.env.BLOG_DB;

  if (!db) {
    return c.json({ error: 'BLOG_DB not configured' }, 501);
  }

  try {
    const body = await c.req.json();
    const { title, content, slug, excerpt, author_id, status, featured_image_url } = body;

    if (!title || !content || !author_id) {
      return c.json({ error: 'title, content, and author_id required' }, 400);
    }

    const id = crypto.randomUUID();
    const postSlug = slug || title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const postExcerpt = excerpt || content.slice(0, 320);
    const now = Math.floor(Date.now() / 1000);

    await db.prepare(`
      INSERT INTO posts (id, title, slug, content, excerpt, author_id, status, featured_image_url, created_at, updated_at, published_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      title,
      postSlug,
      content,
      postExcerpt,
      author_id,
      status || 'draft',
      featured_image_url || null,
      now,
      now,
      status === 'published' ? now : null
    ).run();

    return c.json({ success: true, id, slug: postSlug }, 201);
  } catch (err: any) {
    console.error('Blog post create error:', err);
    return c.json({ error: 'Failed to create post', details: err.message }, 500);
  }
});

// Update post
app.patch('/blog/posts/:id', async (c) => {
  const postId = c.req.param('id');
  const db = c.env.BLOG_DB;

  if (!db) {
    return c.json({ error: 'BLOG_DB not configured' }, 501);
  }

  try {
    const body = await c.req.json();
    const updates: string[] = [];
    const values: any[] = [];

    if (body.title !== undefined) {
      updates.push('title = ?');
      values.push(body.title);
    }
    if (body.content !== undefined) {
      updates.push('content = ?');
      values.push(body.content);
    }
    if (body.excerpt !== undefined) {
      updates.push('excerpt = ?');
      values.push(body.excerpt);
    }
    if (body.slug !== undefined) {
      updates.push('slug = ?');
      values.push(body.slug);
    }
    if (body.status !== undefined) {
      updates.push('status = ?');
      values.push(body.status);
      if (body.status === 'published') {
        updates.push('published_at = ?');
        values.push(Math.floor(Date.now() / 1000));
      }
    }
    if (body.featured_image_url !== undefined) {
      updates.push('featured_image_url = ?');
      values.push(body.featured_image_url);
    }

    updates.push('updated_at = ?');
    values.push(Math.floor(Date.now() / 1000));

    values.push(postId);
    await db.prepare(`UPDATE posts SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();

    return c.json({ success: true });
  } catch (err: any) {
    console.error('Blog post update error:', err);
    return c.json({ error: 'Failed to update post' }, 500);
  }
});

// Delete post
app.delete('/blog/posts/:id', async (c) => {
  const postId = c.req.param('id');
  const db = c.env.BLOG_DB;

  if (!db) {
    return c.json({ error: 'BLOG_DB not configured' }, 501);
  }

  try {
    await db.prepare('DELETE FROM posts WHERE id = ?').bind(postId).run();
    return c.json({ success: true });
  } catch (err: any) {
    console.error('Blog post delete error:', err);
    return c.json({ error: 'Failed to delete post' }, 500);
  }
});

// =============================================================================
// CHAT ROUTES (for API worker to call via service binding)
// Uses CHAT_DB for messages storage
// =============================================================================

// Get messages for a user or room
app.get('/chat/messages', async (c) => {
  const db = c.env.CHAT_DB;
  
  if (!db) {
    return c.json({ error: 'CHAT_DB not configured' }, 501);
  }
  
  try {
    const userId = c.req.query('user_id');
    const roomId = c.req.query('room_id');
    const limit = parseInt(c.req.query('limit') || '50');
    const offset = parseInt(c.req.query('offset') || '0');
    
    let query: string;
    let params: any[];
    
    if (roomId) {
      query = `SELECT * FROM messages WHERE room_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;
      params = [roomId, limit, offset];
    } else if (userId) {
      query = `SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;
      params = [userId, limit, offset];
    } else {
      return c.json({ error: 'user_id or room_id required' }, 400);
    }
    
    const { results } = await db.prepare(query).bind(...params).all();
    return c.json({ messages: results, total: results.length });
  } catch (err: any) {
    console.error('Chat messages fetch error:', err);
    return c.json({ error: 'Failed to fetch messages' }, 500);
  }
});

// Create a new message
app.post('/chat/messages', async (c) => {
  const db = c.env.CHAT_DB;
  
  if (!db) {
    return c.json({ error: 'CHAT_DB not configured' }, 501);
  }
  
  try {
    const body = await c.req.json();
    const { room_id, user_id, content, type } = body;
    
    if (!room_id || !user_id || !content) {
      return c.json({ error: 'room_id, user_id, and content required' }, 400);
    }
    
    const id = crypto.randomUUID();
    await db.prepare(`
      INSERT INTO messages (id, room_id, user_id, content, type, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(id, room_id, user_id, content, type || 'text').run();
    
    return c.json({ success: true, id }, 201);
  } catch (err: any) {
    console.error('Chat message create error:', err);
    return c.json({ error: 'Failed to create message' }, 500);
  }
});

// Moderate a message (delete or flag)
app.post('/chat/moderation', async (c) => {
  const db = c.env.CHAT_DB;
  
  if (!db) {
    return c.json({ error: 'CHAT_DB not configured' }, 501);
  }
  
  try {
    const body = await c.req.json();
    const { messageId, action, reason, adminId } = body;
    
    if (!messageId || !action) {
      return c.json({ error: 'messageId and action required' }, 400);
    }
    
    if (action === 'delete') {
      await db.prepare(`UPDATE messages SET deleted_at = datetime('now') WHERE id = ?`).bind(messageId).run();
    } else if (action === 'flag') {
      // If you have a flagged column, update it
      // For now, just log
      console.log(`Message ${messageId} flagged by ${adminId}: ${reason}`);
    }
    
    return c.json({ success: true, action, messageId });
  } catch (err: any) {
    console.error('Chat moderation error:', err);
    return c.json({ error: 'Failed to moderate message' }, 500);
  }
});

// Delete a chat room
app.delete('/chat/rooms/:id', async (c) => {
  const db = c.env.CHAT_DB;
  const roomId = c.req.param('id');
  
  if (!db) {
    return c.json({ error: 'CHAT_DB not configured' }, 501);
  }
  
  try {
    // Delete messages first (foreign key constraint)
    await db.prepare('DELETE FROM messages WHERE room_id = ?').bind(roomId).run();
    await db.prepare('DELETE FROM chat_rooms WHERE id = ?').bind(roomId).run();
    return c.json({ success: true });
  } catch (err: any) {
    console.error('Chat room delete error:', err);
    return c.json({ error: 'Failed to delete room' }, 500);
  }
});

// List chat rooms
app.get('/chat/rooms', async (c) => {
  const db = c.env.CHAT_DB;
  
  if (!db) {
    return c.json({ error: 'CHAT_DB not configured' }, 501);
  }
  
  try {
    const { results } = await db.prepare(`
      SELECT id, name, description, type, owner_id, created_at
      FROM chat_rooms
      ORDER BY created_at DESC
      LIMIT 100
    `).all();
    return c.json({ rooms: results });
  } catch (err: any) {
    console.error('Chat rooms list error:', err);
    return c.json({ error: 'Failed to fetch rooms' }, 500);
  }
});

// Get messages for a specific room
app.get('/chat/rooms/:id/messages', async (c) => {
  const db = c.env.CHAT_DB;
  const roomId = c.req.param('id');
  
  if (!db) {
    return c.json({ error: 'CHAT_DB not configured' }, 501);
  }
  
  try {
    const limit = parseInt(c.req.query('limit') || '50');
    const { results } = await db.prepare(`
      SELECT id, room_id, user_id, content, type, created_at
      FROM messages
      WHERE room_id = ?
      ORDER BY created_at ASC
      LIMIT ?
    `).bind(roomId, limit).all();
    return c.json(results);
  } catch (err: any) {
    console.error('Room messages fetch error:', err);
    return c.json({ error: 'Failed to fetch messages' }, 500);
  }
});

export default app;
