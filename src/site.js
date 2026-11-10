const express = require('express');

const router = express.Router();
const HOST = process.env.PUBLIC_URL || 'https://bench.lab.securityphoenix.ai';

const links = [
  ['/api/products?q=widget', 'Search products'],
  ['/api/lookup?host=localhost', 'Host lookup'],
  ['/api/files?name=welcome.txt', 'Read a document'],
  ['/api/fetch?url=https://example.com', 'Fetch a URL'],
  ['/api/calc?expr=1%2B1', 'Calculator'],
  ['/api/system/info', 'System info'],
  ['/api/debug/env', 'Debug environment'],
  ['/api/me', 'Current user'],
  ['/api', 'API index (JSON)'],
  ['/openapi.json', 'OpenAPI description'],
];

router.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Shop API</title></head>
<body>
<h1>Shop API</h1>
<ul>${links.map(([h, t]) => `<li><a href="${h}">${t}</a></li>`).join('\n')}</ul>
<h2>Sign in</h2>
<form method="post" action="/api/login">
  <label>User <input name="username"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Sign in</button>
</form>
<h2>Upload</h2>
<form method="post" action="/api/upload?name=file.txt" enctype="application/octet-stream">
  <input type="file" name="file"><button type="submit">Upload</button>
</form>
</body></html>`);
});

router.get('/robots.txt', (req, res) =>
  res.type('text/plain').send(`User-agent: *\nAllow: /\nSitemap: ${HOST}/sitemap.xml\n`));

router.get('/sitemap.xml', (req, res) => {
  const urls = ['/', ...links.map(([h]) => h)].map((u) => `<url><loc>${HOST}${u.replace(/&/g, '&amp;')}</loc></url>`);
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`);
});

router.get('/openapi.json', (req, res) => {
  const q = (name, example) => ({ name, in: 'query', required: true, schema: { type: 'string' }, example });
  const get = (summary, params = []) => ({ get: { summary, parameters: params, responses: { 200: { description: 'OK' } } } });
  res.json({
    openapi: '3.0.3',
    info: { title: 'Shop API', version: '1.0.0' },
    servers: [{ url: HOST }],
    paths: {
      '/api/login': {
        post: {
          summary: 'Sign in',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { username: { type: 'string' }, password: { type: 'string' } } } } } },
          responses: { 200: { description: 'Token' }, 401: { description: 'Bad credentials' } },
        },
      },
      '/api/products': get('Search products', [q('q', 'widget')]),
      '/api/lookup': get('Host lookup', [q('host', 'localhost')]),
      '/api/files': get('Read a document', [q('name', 'welcome.txt')]),
      '/api/fetch': get('Fetch a URL', [q('url', 'https://example.com')]),
      '/api/calc': get('Calculator', [q('expr', '1+1')]),
      '/api/debug/env': get('Debug environment'),
      '/api/system/info': get('System info'),
      '/api/me': get('Current user'),
      '/api/upload': {
        post: {
          summary: 'Upload a file',
          parameters: [q('name', 'file.txt')],
          requestBody: { content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } },
          responses: { 200: { description: 'URL of the stored file' } },
        },
      },
    },
  });
});

module.exports = router;
