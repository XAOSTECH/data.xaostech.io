export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // GDPR consent endpoint
    if (url.pathname === '/api/consent' && request.method === 'POST') {
      const { userId, accepted, categories } = await request.json();
      
      try {
        await env.CONSENT_KV.put(
          `consent:${userId}`,
          JSON.stringify({ userId, accepted, categories, timestamp: Date.now() })
        );
        
        const headers = new Headers({ 'Content-Type': 'application/json' });
        headers.append('Set-Cookie', `consent=${userId}; Domain=${env.COOKIE_DOMAIN}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000`);
        
        return new Response(JSON.stringify({ success: true }), { headers });
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Failed to save consent' }), { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Privacy policy
    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(`
        <!DOCTYPE html>
        <html>
        <head><title>Privacy Policy</title></head>
        <body>
          <h1>Privacy Policy</h1>
          <p>XAOSTECH is committed to your privacy.</p>
          <ul>
            <li>No collection by default</li>
            <li>Explicit consent required</li>
            <li>SameSite=Strict cookies</li>
            <li>Data deletion on request</li>
          </ul>
        </body>
        </html>
      `, { 
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    return new Response('Not found', { status: 404 });
  }
};
