/**
 * VulnBank — Deliberately Insecure Express App
 *
 * PURPOSE: Demo target for the SecuraAI scanner.
 * Every vulnerability here is INTENTIONAL so the scanner has real targets to find.
 *
 * Runs both locally (node server.js) and on Vercel (serverless).
 */

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');  // pinned to 8.5.1 — known CVE for OSV-Scanner to catch
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();

// ─────────────────────────────────────────────────────────────────────────────
// VULN-1: Hardcoded secrets (Gitleaks will flag these)
// ─────────────────────────────────────────────────────────────────────────────
const JWT_SECRET        = 'hardcoded_jwt_secret_do_not_use';   // gitleaks: jwt-secret
const DB_PASSWORD       = 'S3cr3tP@ssw0rd!';                  // gitleaks: password
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';             // gitleaks: aws-access-key-id
const STRIPE_KEY        = 'sk_live_DEMO_FAKE_KEY_DO_NOT_USE_1234567890'; // gitleaks: stripe-secret-key

// ─────────────────────────────────────────────────────────────────────────────
// In-memory DB (no native modules — works on Vercel serverless)
// ─────────────────────────────────────────────────────────────────────────────
const users = [
  { id: 1, username: 'admin', password: 'supersecret123', role: 'admin', email: 'admin@vulnbank.local', balance: 99999 },
  { id: 2, username: 'alice', password: 'alice1234',      role: 'user',  email: 'alice@vulnbank.local', balance: 1500  },
  { id: 3, username: 'bob',   password: 'password123',   role: 'user',  email: 'bob@vulnbank.local',   balance: 250   },
];

const transactions = [
  { id: 1, from_id: 2, to_id: 3, amount: 100, note: 'Lunch' },
];

let nextUserId = 4;

// ─────────────────────────────────────────────────────────────────────────────
// VULN-2: Intentionally weak HTTP response headers (Header Audit will flag these)
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Express 1.0 Vulnerable');
    // Missing: Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy
    // Weak CSP: allows everything
    res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:");
    // X-Frame-Options missing — clickjacking possible
    // Set-Cookie without HttpOnly or Secure
    res.setHeader('Set-Cookie', `sessionid=${crypto.randomBytes(4).toString('hex')}; Path=/`);
    next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────────────────────
// VULN-3: SQL Injection — Login (simulated — Semgrep will still catch the pattern)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // INTENTIONALLY VULNERABLE: simulates string concatenation into SQL
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    // In-memory equivalent (still demonstrates SQLi pattern for SAST)
    const row = users.find(u => u.username === username && u.password === password);

    if (row) {
        // VULN: algorithm not specified — vulnerable to algorithm confusion attack
        const token = jwt.sign({ id: row.id, role: row.role }, JWT_SECRET);
        res.json({ success: true, token, user: row, debug_query: sql });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials', debug_query: sql });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-4: SQL Injection — User search GET (Semgrep)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
    const q = req.query.q || '';

    // INTENTIONALLY VULNERABLE (pattern preserved for SAST detection)
    const _vuln_sql = `SELECT id, username, role, email, balance FROM users WHERE username LIKE '%${q}%'`;

    const filtered = q
        ? users.filter(u => u.username.includes(q))
        : users;

    res.json({ users: filtered.map(u => ({ id: u.id, username: u.username, role: u.role, email: u.email, balance: u.balance })), debug_query: _vuln_sql });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-5: SQL Injection — Transaction lookup by ID
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/transactions/:id', (req, res) => {
    const id = req.params.id;

    // INTENTIONALLY VULNERABLE: param goes straight into SQL (pattern for SAST)
    const _vuln_sql = `SELECT * FROM transactions WHERE from_id = ` + id;

    const rows = transactions.filter(t => t.from_id == id);
    res.json({ transactions: rows, debug_query: _vuln_sql });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-6: Command Injection (Semgrep: javascript.lang.security.detect-child-process)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ping', (req, res) => {
    const { host } = req.body;

    // INTENTIONALLY VULNERABLE: unsanitised user input in exec()
    exec(`ping -n 1 ${host}`, (error, stdout, stderr) => {
        if (error) return res.status(500).send(error.message);
        res.send(stdout || stderr);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-7: Path Traversal (Semgrep: detect-non-literal-fs-filename)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/file', (req, res) => {
    const { name } = req.query;
    const fs = require('fs');

    // INTENTIONALLY VULNERABLE: no path sanitisation
    const filePath = path.join(__dirname, 'uploads', name);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-8: Weak cryptography — MD5 password hashing (Semgrep)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;

    // INTENTIONALLY VULNERABLE: MD5 is cryptographically broken
    const hashed = crypto.createHash('md5').update(password).digest('hex');

    // INTENTIONALLY VULNERABLE SQL pattern (preserved for SAST detection)
    const _vuln_sql = `INSERT INTO users (username, password, role) VALUES ('${username}', '${hashed}', 'user')`;

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists', debug_query: _vuln_sql });
    }
    users.push({ id: nextUserId++, username, password: hashed, role: 'user', email: '', balance: 0 });
    res.json({ success: true, hashed_password: hashed, debug_query: _vuln_sql });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-9: Insecure Eval (Semgrep: detect-eval-with-expression)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/calculate', (req, res) => {
    const { expression } = req.body;

    // INTENTIONALLY VULNERABLE: eval() on user input = RCE
    try {
        const result = eval(expression); // eslint-disable-line no-eval
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Recon targets — sensitive paths the crawler should discover
// ─────────────────────────────────────────────────────────────────────────────
app.get('/.env', (req, res) => {
    res.type('text/plain').send([
        `DB_HOST=localhost`,
        `DB_USER=root`,
        `DB_PASS=${DB_PASSWORD}`,
        `JWT_SECRET=${JWT_SECRET}`,
        `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}`,
        `STRIPE_SECRET_KEY=${STRIPE_KEY}`,
    ].join('\n'));
});

app.get('/admin', (req, res) => {
    res.json({ message: 'Admin panel — no auth required!', users: ['admin', 'alice', 'bob'] });
});

app.get('/admin/backup.sql', (req, res) => {
    res.type('text/plain').send(`INSERT INTO users VALUES (1,'admin','supersecret123','admin','admin@vulnbank.local',99999);`);
});

app.get('/api/internal/metrics', (req, res) => {
    res.json({ requests_per_second: 120, error_rate: 0.02, db_connections: 5 });
});

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok', environment: process.env.VERCEL ? 'vercel' : 'local' }));

// ─────────────────────────────────────────────────────────────────────────────
// Fallback — serve public/index.html for all unmatched routes
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────────────────────────────────────
// Start: local dev uses listen(), Vercel uses module.exports
// ─────────────────────────────────────────────────────────────────────────────
if (require.main === module) {
    const PORT = process.env.PORT || 4000;
    app.listen(PORT, () => {
        console.log(`\n  VulnBank Demo Target`);
        console.log(`  ─────────────────────────────────────────`);
        console.log(`  Running at  http://localhost:${PORT}`);
        console.log(`  ⚠  Intentionally insecure — demo only!\n`);
    });
}

module.exports = app;
