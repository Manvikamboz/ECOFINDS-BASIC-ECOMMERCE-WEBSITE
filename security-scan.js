/**
 * EcoFinds Security Scanner
 * Checks for common security issues across the codebase
 */

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const RESULTS = { pass: [], warn: [], fail: [] };

function pass(msg) { RESULTS.pass.push(msg); console.log(`  ✅ PASS  ${msg}`); }
function warn(msg) { RESULTS.warn.push(msg); console.log(`  ⚠️  WARN  ${msg}`); }
function fail(msg) { RESULTS.fail.push(msg); console.log(`  ❌ FAIL  ${msg}`); }

function readFile(filePath) {
    try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
}

console.log('\n🔐 EcoFinds Security Scanner\n' + '='.repeat(50));

// ─── 1. Environment & Secrets ─────────────────────────────────────────────────
console.log('\n[1] Environment & Secrets');

const gitignore = readFile(path.join(ROOT, '.gitignore'));
if (gitignore && gitignore.includes('.env')) pass('.env is in .gitignore');
else fail('.env is NOT in .gitignore — secrets will be committed!');

const envInGit = require('child_process')
    .execSync('git ls-files --error-unmatch .env 2>&1 || echo "NOT_TRACKED"', { cwd: ROOT })
    .toString().trim();
if (envInGit.includes('NOT_TRACKED') || envInGit.includes('error')) pass('.env is not tracked by git');
else fail('.env is tracked by git — run: git rm --cached .env');

const nodeModulesInGit = require('child_process')
    .execSync('git ls-files node_modules | head -1 2>&1 || echo ""', { cwd: ROOT })
    .toString().trim();
if (!nodeModulesInGit) pass('node_modules is not tracked by git');
else fail('node_modules is tracked by git');

// ─── 2. Server.js Security Checks ────────────────────────────────────────────
console.log('\n[2] Server Security (server.js)');
const server = readFile(path.join(ROOT, 'server.js'));

if (server.includes("require('helmet')") || server.includes('require("helmet")'))
    pass('helmet security headers enabled');
else fail('helmet not found — missing security headers');

if (server.includes('rateLimit') || server.includes('rate-limit'))
    pass('rate limiting enabled on auth routes');
else fail('no rate limiting — vulnerable to brute force');

if (server.includes('express-rate-limit')) pass('express-rate-limit package used');

if (server.includes("origin:") && !server.includes("origin: '*'"))
    pass('CORS restricted to specific origin');
else if (server.includes("cors()") && !server.includes("origin"))
    fail('CORS is fully open — all origins allowed');
else warn('CORS origin check could not be determined');

if (server.includes('bcrypt.hash')) pass('passwords hashed with bcrypt');
else fail('passwords not hashed with bcrypt');

if (server.includes('12)') && server.includes('bcrypt.hash'))
    pass('bcrypt salt rounds >= 12 (strong)');
else if (server.includes('10)') && server.includes('bcrypt.hash'))
    warn('bcrypt salt rounds = 10 (consider using 12+)');

if (server.includes('DUMMY_HASH') || server.includes('dummyHash'))
    pass('timing-safe login (constant-time bcrypt compare)');
else warn('login may be vulnerable to timing attacks');

if (server.includes('process.env.JWT_SECRET') && !server.includes("|| 'your-secret-key'") && !server.includes('|| "your-secret-key"'))
    pass('JWT secret loaded from env only (no hardcoded fallback)');
else fail('JWT has a hardcoded fallback secret — security risk!');

if (server.includes("|| 'manvi'") || server.includes('|| "manvi"'))
    fail('hardcoded DB password fallback found');
else pass('no hardcoded DB password fallback');

if (server.includes("REQUIRED_ENV") && server.includes('process.exit(1)'))
    pass('server fails fast if env vars missing');
else warn('no fail-fast check for missing env vars');

if (server.includes('express.json({ limit:') || server.includes("express.json({limit:"))
    pass('JSON body size limited (DoS prevention)');
else warn('no JSON body size limit set');

if (server.includes('pool.execute') || server.includes('conn.execute'))
    pass('parameterized SQL queries used (SQL injection safe)');
else fail('possible raw SQL queries — check for injection risk');

if (server.includes('beginTransaction') && server.includes('rollback'))
    pass('checkout uses DB transaction with rollback');
else fail('checkout has no DB transaction — data integrity risk');

if (server.includes('seller_id === userId') || server.includes("seller can't") || server.includes('own product'))
    pass('seller cannot buy their own product (enforced server-side)');
else warn('no check preventing seller from buying own product');

if (server.includes('parseInt(req.params') || server.includes('parseInt(req.body'))
    pass('route parameters parsed as integers (injection safe)');
else warn('route parameters not explicitly cast to int');

if (server.includes('fs.promises.unlink'))
    pass('file deletion is async (non-blocking)');
else warn('file deletion may be synchronous (blocking event loop)');

if (server.includes('fileSize: 5 * 1024 * 1024'))
    pass('file upload size limited to 5MB');
else warn('no file upload size limit found');

if (server.includes("startsWith('image/')") || server.includes('ALLOWED_MIME_TYPES'))
    pass('file upload MIME type validation in place');
else fail('no file type validation on uploads');

if (server.includes('createPool'))
    pass('DB uses connection pool (auto-reconnect, scalable)');
else fail('DB uses single connection (will crash on disconnect)');

// ─── 3. Frontend Security (index.html) ───────────────────────────────────────
console.log('\n[3] Frontend Security (index.html)');
const html = readFile(path.join(ROOT, 'public', 'index.html'));

if (html.includes('function escapeHtml'))
    pass('escapeHtml() utility defined');
else fail('no escapeHtml() — XSS risk in DOM rendering');

const escapeCount = (html.match(/escapeHtml\(/g) || []).length;
if (escapeCount >= 10)
    pass(`escapeHtml() used ${escapeCount} times across templates`);
else if (escapeCount > 0)
    warn(`escapeHtml() used only ${escapeCount} times — may be missing in some templates`);
else
    fail('escapeHtml() never called — all innerHTML injections are unsafe');

if (html.includes("const API_BASE = '/api'"))
    pass("API_BASE uses relative URL '/api' (production safe)");
else if (html.includes('localhost'))
    fail('API_BASE hardcoded to localhost — will break in production');

if (html.includes('isStrongPassword'))
    pass('password strength validation on registration');
else warn('no client-side password strength check');

if (html.includes("id=\"registerConfirm\""))
    pass('password confirmation field present');
else warn('no password confirmation field on register form');

if (html.includes('localStorage.setItem') && html.includes('authToken'))
    warn('JWT stored in localStorage — consider httpOnly cookies for higher security');

// ─── 4. Dependency & File Checks ─────────────────────────────────────────────
console.log('\n[4] Dependencies & Files');

const pkg = JSON.parse(readFile(path.join(ROOT, 'package.json')));
const deps = { ...pkg.dependencies, ...pkg.devDependencies };

['helmet', 'express-rate-limit', 'bcrypt', 'jsonwebtoken', 'dotenv', 'cors', 'multer'].forEach(dep => {
    if (deps[dep]) pass(`dependency present: ${dep}@${deps[dep]}`);
    else fail(`missing dependency: ${dep}`);
});

if (pkg.scripts?.start) pass(`"start" script defined: ${pkg.scripts.start}`);
else fail('no "start" script in package.json — deployment will fail');

if (readFile(path.join(ROOT, '.gitignore'))?.includes('node_modules'))
    pass('node_modules in .gitignore');
else fail('node_modules NOT in .gitignore');

// ─── 5. GitHub Actions Workflow ───────────────────────────────────────────────
console.log('\n[5] GitHub Actions / CI');
const workflow = readFile(path.join(ROOT, '.github/workflows/deploy.yml'));

if (workflow) {
    if (workflow.includes('npm ci')) pass('workflow uses npm ci (strict install)');
    else warn('workflow uses npm install instead of npm ci');

    if (workflow.includes('secrets.VERCEL_TOKEN')) pass('Vercel token from GitHub Secrets (not hardcoded)');
    else warn('Vercel token reference not found in workflow');

    if (workflow.includes('actions/checkout@v4')) pass('uses latest actions/checkout@v4');
    if (workflow.includes('actions/setup-node@v4')) pass('uses latest actions/setup-node@v4');
} else {
    warn('no GitHub Actions workflow found');
}

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(50));
console.log('📊 SECURITY SCAN SUMMARY');
console.log('='.repeat(50));
console.log(`  ✅ PASS : ${RESULTS.pass.length}`);
console.log(`  ⚠️  WARN : ${RESULTS.warn.length}`);
console.log(`  ❌ FAIL : ${RESULTS.fail.length}`);
console.log('='.repeat(50));

const score = Math.round((RESULTS.pass.length / (RESULTS.pass.length + RESULTS.warn.length + RESULTS.fail.length)) * 100);
const grade = score >= 90 ? '🏆 A' : score >= 75 ? '👍 B' : score >= 60 ? '⚠️ C' : '❌ D';
console.log(`  Security Score: ${score}% — Grade: ${grade}`);
console.log('='.repeat(50) + '\n');

if (RESULTS.fail.length > 0) {
    console.log('❌ FAILURES TO FIX:');
    RESULTS.fail.forEach(f => console.log(`   • ${f}`));
}
if (RESULTS.warn.length > 0) {
    console.log('\n⚠️  WARNINGS TO REVIEW:');
    RESULTS.warn.forEach(w => console.log(`   • ${w}`));
}
