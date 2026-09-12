"""Browser-independent execution tests for the synchronous auth boundary."""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_js(body):
    script = """
const fs = require('fs'); const vm = require('vm'); const assert = require('assert');
const calls = [];
global.window = global;
global.location = {href:'http://localhost/dns_frontend.html',origin:'http://localhost',pathname:'/dns_frontend.html',replace: p=>{global.redirect=p;}};
global.document = {readyState:'loading',addEventListener:()=>{},getElementById:()=>null};
global.fetch = async (url, options={}) => {calls.push({url:String(url),options}); return new Response(JSON.stringify(String(url).endsWith('/auth/me') ? {user:{id:1,username:'reader',role:'viewer'},csrf_token:'test-token'} : {status:'ok'}), {status:200,headers:{'Content-Type':'application/json'}});};
vm.runInThisContext(fs.readFileSync('auth_frontend.js','utf8'));
(async()=>{
""" + body + "\n})().catch(e=>{console.error(e);process.exit(1)});"
    result = subprocess.run(['node', '-e', script], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_wrapper_waits_for_identity_and_limits_viewer_enrichment():
    assert (ROOT / 'auth_frontend.js').exists(), 'auth boundary missing'
    run_js("""
await fetch('/ips?include_vt=1');
assert.equal(calls[0].url, '/auth/me');
assert.equal(new URL(calls[1].url, location.origin).searchParams.get('include_vt'), '0');
await fetch('/auth/logout',{method:'POST',body:'{}'});
assert.equal(new Headers(calls[2].options.headers).get('X-CSRF-Token'),'test-token');
await fetch('https://example.test/data',{method:'POST'});
assert.equal(new Headers(calls[3].options.headers).has('X-CSRF-Token'),false);
""")


def test_security_pages_load_auth_before_ui_and_have_accessible_forms():
    for name, form in [("login","login-form"),("account","password-form"),("accounts","create-user-form"),("audit","audit-filter-form")]:
        path = ROOT / (name + ".html")
        assert path.exists(), name + " page missing"
        html = path.read_text()
        assert html.index("/auth_frontend.js") < html.index("/security_ui.js")
        assert form in html
        assert "role=\"status\"" in html
