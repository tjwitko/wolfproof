import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { checkAuthentication, authenticationFailures, leakyCredentialCheck, isProbeRoute } from "./authentication.mjs";

// These fixtures often carry more than one real defect -- a credential compared with `!=` against
// an unset env var is BOTH vacuous and timing-unsafe. Asserting on totals would make every test
// brittle to a new finding; assert on the finding under test instead.
const vacuous = (failures) => failures.filter((f) => /does not fail closed/.test(f));

function run(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "auth-"));
  for (const [rel, contents] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents);
  }
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// The trap this check exists to avoid. A real run had Depends(get_db) on every route and
// authenticated none of them; anything matching on `Depends(` alone would have passed it.
test("a database session dependency is not authentication", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.post('/logs')\ndef create_log(log: X, db: Session = Depends(get_db)):\n    pass\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
});

test("an auth dependency or a credential header counts", () => {
  const dep = run(
    { "app/main.py": "@app.get('/logs')\ndef read(user = Depends(get_current_user)):\n    pass\n" },
    authenticationFailures
  );
  assert.deepEqual(dep.failures, []);

  // The handler must actually CHECK the credential. `pass` here originally passed the gate, which
  // meant a handler that ignored its own api-key header was reported as authenticated.
  const header = run(
    {
      "app/main.py":
        "@app.post('/logs')\ndef add(x_api_key: str = Header(...)):\n" +
        "    if not compare_digest(x_api_key, API_KEY):\n        raise HTTPException(status_code=403)\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(header.failures, []);
});

// Per route, not per project. A real run authenticated POST and left GET open; a project-level
// "is there any auth here" test would have called that done.
test("a partially protected surface still fails, and says so", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.post('/logs')\ndef add(x_api_key: str = Header(...)):\n" +
        "    if not compare_digest(x_api_key, API_KEY):\n        raise HTTPException(status_code=403)\n    pass\n\n" +
        "@app.get('/logs')\ndef read(limit: int = 50):\n    pass\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /1 of 2 endpoint\(s\)/);
  assert.match(failures[0], /GET \/logs/);
  assert.match(failures[0], /gap rather than an omission/);
});

test("an application-wide dependency protects every route", () => {
  const { failures } = run(
    {
      "app/main.py":
        "app = FastAPI(dependencies=[Depends(verify_api_key)])\n\n" +
        "@app.get('/logs')\ndef read():\n    pass\n\n@app.post('/logs')\ndef add():\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

test("a route-level dependencies= list counts", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.get('/logs', dependencies=[Depends(verify_api_key)])\ndef read():\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// A liveness probe that requires a credential is a liveness probe that fails.
test("health and readiness probes are exempt", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.get('/health')\ndef health():\n    pass\n\n" +
        "@app.get('/metrics')\ndef metrics():\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// Exempt is not invisible. A probe's /ping took a request parameter and passed it to a shell; it was
// skipped by name, and the finding counted "1 of 1 endpoint(s)" in a file declaring two.
test("exempt routes are named, with why, beside the finding", () => {
  const { failures, advisories } = run(
    {
      "app.py":
        "@app.get('/ping')\ndef ping():\n    return subprocess.run('ping -c1 ' + request.args['host'], shell=True)\n\n" +
        "@app.post('/login')\ndef login():\n    pass\n\n" +
        "@app.get('/user')\ndef user():\n    pass\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /1 of 1 endpoint\(s\).*2 more are exempt by name/);
  assert.equal(advisories.length, 1);
  assert.match(advisories[0], /2 route\(s\) exempt by name, not checked/);
  assert.match(advisories[0], /GET \/ping \(app\.py:1, probe\)/);
  assert.match(advisories[0], /POST \/login \(app\.py:\d+, issues a credential\)/);
});

test("exemptions are reported when every other route is protected, too", () => {
  const { failures, advisories } = run(
    {
      "app/main.py":
        "app = FastAPI(dependencies=[Depends(verify_api_key)])\n\n" +
        "@app.get('/health')\ndef health():\n    pass\n\n@app.get('/logs')\ndef logs():\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
  assert.match(advisories.join("\n"), /GET \/health \(app\/main\.py:3, probe\)/);
});

// It said "no HTTP routes were identified", which was false: they were identified, then skipped.
test("a service whose only routes are exempt says so, rather than that it found none", () => {
  const { failures, advisories } = run(
    { "app.py": "@app.get('/ping')\ndef ping():\n    pass\n" },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
  assert.match(advisories[0], /the only routes identified are exempt by name.*GET \/ping \(app\.py:1, probe\)/);
  assert.doesNotMatch(advisories[0], /no HTTP routes were identified/);
});

// Narrow on purpose: an ordinary header is not a credential, and a check that says otherwise
// reports every route as protected.
test("an ordinary header is not authentication", () => {
  const { failures } = run(
    { "app/main.py": "@app.get('/logs')\ndef read(user_agent: str = Header(None)):\n    pass\n" },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
});

test("an undetermined answer is reported, never passed silently", () => {
  const report = run({ "app/util.py": "def helper():\n    return 1\n" }, checkAuthentication);
  assert.ok(report.unknown);
  const { failures, advisories } = run({ "app/util.py": "def helper():\n    return 1\n" }, authenticationFailures);
  assert.deepEqual(failures, []);
  assert.equal(advisories.length, 1);
});

// ---------------------------------------------------------------------------------------------
// JavaScript / TypeScript
//
// The reason this file grew. Run against this repo's own Express reference project -- which
// authenticates nothing -- the Python-only check reported "not checked, no Python source files
// found" and could not block. These pin the behaviour that replaced it.
// ---------------------------------------------------------------------------------------------

test("express: an unprotected route fails, and names method and path", () => {
  const { failures } = run(
    { "src/app.js": "const app = express();\napp.post('/logs', (req, res) => res.send('ok'));\n" },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
});

test("express: route middleware counts as authentication", () => {
  const { failures } = run(
    { "src/app.js": "app.post('/logs', requireAuth, (req, res) => res.send('ok'));\n" },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

test("express: an app-wide use() protects every route", () => {
  const { failures } = run(
    { "src/app.js": "app.use(authenticateRequest);\napp.get('/logs', list);\napp.post('/logs', create);\n" },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// The single most likely false positive in Express, and the reason the path must start with `/`
// and be followed by a comma: `app.get(name)` is the settings *getter*, and it appears in
// virtually every Express application.
test("express: app.get('port') is a settings read, not a route", () => {
  const report = run(
    { "src/app.js": "app.set('port', 3000);\nconst port = app.get('port');\nconst env = app.get('env');\n" },
    checkAuthentication
  );
  assert.equal(report.routes.length, 0);
  assert.ok(report.unknown, "no routes reported, and that is undetermined rather than a pass");
});

// Same guard, different shape: ordinary collection calls take string keys too.
test("express: map.delete and cache.get are not routes", () => {
  const report = run(
    {
      "src/store.js":
        "cache.get('user:1');\nsessions.delete('abc');\nheaders.get('content-type');\napp.post('/logs', create);\n",
    },
    checkAuthentication
  );
  assert.equal(report.routes.length, 1);
  assert.equal(report.routes[0].route, "/logs");
});

test("express: non-auth middleware does not count as authentication", () => {
  const { failures } = run(
    {
      "src/app.js":
        "app.use(cors());\napp.use(express.json());\napp.use(morgan('dev'));\napp.post('/logs', create);\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
});

// `login` is deliberately absent from the auth vocabulary: a handler that issues a credential is
// not a handler that checks one.
test("express: a handler named loginHandler does not protect a route", () => {
  const { failures } = run({ "src/app.js": "app.post('/logs', loginHandler);\n" }, authenticationFailures);
  assert.equal(failures.length, 1);
});

test("express: chained app.route() is judged per verb", () => {
  const { failures } = run(
    { "src/app.js": "app.route('/logs')\n  .get(list)\n  .post(requireAuth, create);\n" },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /GET \/logs/);
  assert.doesNotMatch(failures[0], /POST \/logs/);
});

test("fastify: a preHandler hook counts, its absence does not", () => {
  const withHook = run(
    {
      "src/server.js":
        "fastify.route({ method: 'POST', url: '/logs', preHandler: fastify.authenticate, handler: create });\n",
    },
    authenticationFailures
  );
  assert.deepEqual(withHook.failures, []);

  const without = run(
    { "src/server.js": "fastify.route({ method: 'POST', url: '/logs', handler: create });\n" },
    authenticationFailures
  );
  assert.equal(without.failures.length, 1);
  assert.match(without.failures[0], /POST \/logs/);
});

test("nestjs: @UseGuards on the method protects it", () => {
  const guarded = run(
    {
      "src/logs.controller.ts":
        "@Controller('logs')\nexport class LogsController {\n  @UseGuards(AuthGuard)\n  @Post('/logs')\n  create() {}\n}\n",
    },
    authenticationFailures
  );
  assert.deepEqual(guarded.failures, []);

  const bare = run(
    {
      "src/logs.controller.ts":
        "@Controller('logs')\nexport class LogsController {\n  @Post('/logs')\n  create() {}\n}\n",
    },
    authenticationFailures
  );
  assert.equal(bare.failures.length, 1);
});

// ---------------------------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------------------------

test("go: an unprotected chi route fails", () => {
  const { failures } = run({ "main.go": 'r.Post("/logs", createLog)\n' }, authenticationFailures);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
});

test("go: middleware in the chain counts, and Use() protects everything", () => {
  const perRoute = run({ "main.go": 'r.Post("/logs", RequireAuth(createLog))\n' }, authenticationFailures);
  assert.deepEqual(perRoute.failures, []);

  const global = run({ "main.go": 'r.Use(AuthMiddleware)\nr.Get("/logs", listLogs)\n' }, authenticationFailures);
  assert.deepEqual(global.failures, []);
});

// net/http's HandleFunc carries no method, and reporting a guessed one would be worse than none.
test("go: HandleFunc is reported as ANY rather than guessed", () => {
  const report = run({ "main.go": 'http.HandleFunc("/logs", handler)\n' }, checkAuthentication);
  assert.equal(report.routes.length, 1);
  assert.equal(report.routes[0].method, "ANY");
});

// ---------------------------------------------------------------------------------------------
// Java (Spring)
// ---------------------------------------------------------------------------------------------

test("java: a mapping without an authorization annotation fails", () => {
  const { failures } = run(
    {
      "src/LogController.java":
        '@RestController\npublic class LogController {\n  @PostMapping("/logs")\n  public void create() {}\n}\n',
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
});

test("java: @PreAuthorize counts, and a security filter chain protects everything", () => {
  const annotated = run(
    { "src/LogController.java": '@PostMapping("/logs")\n@PreAuthorize("hasRole(\'WRITER\')")\npublic void create() {}\n' },
    authenticationFailures
  );
  assert.deepEqual(annotated.failures, []);

  const chain = run(
    {
      "src/SecurityConfig.java": "http.authorizeHttpRequests(a -> a.anyRequest().authenticated());\n",
      "src/LogController.java": '@GetMapping("/logs")\npublic void list() {}\n',
    },
    authenticationFailures
  );
  assert.deepEqual(chain.failures, []);
});

// ---------------------------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------------------------

test("ruby: a Sinatra route without a before filter fails", () => {
  const { failures } = run({ "app.rb": "post '/logs' do\n  Log.create(params)\nend\n" }, authenticationFailures);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
});

// This test used to say the opposite. `before_action` is Rails: it runs for its own controller's
// actions, never for a Sinatra route, and it marked every Ruby route in the project protected.
test("ruby: a Rails before_action does not protect a Sinatra route", () => {
  const { failures } = run(
    {
      "app.rb":
        "class LogsController\n  before_action :authenticate_user!\nend\n\nget '/logs' do\n  Log.all\nend\n",
    },
    authenticationFailures
  );
  assert.equal(failures.filter((f) => /accept requests from anyone/.test(f)).length, 1);
  assert.match(failures[0], /GET \/logs/);
});

test("ruby: a before filter with a path protects the routes it matches, and only those", () => {
  const report = run(
    {
      "app.rb":
        "require 'sinatra'\n\nbefore '/admin/*' do\n  halt 401 unless session[:admin]\nend\n\n" +
        "before '/accounts/:id' do\n  halt 403 unless session[:user_id]\nend\n\n" +
        "get '/admin/stats' do\n  'stats'\nend\n\nget '/accounts/:id' do\n  'a'\nend\n\n" +
        "get '/accounts/:id/export' do\n  'x'\nend\n\nget '/reports' do\n  '[]'\nend\n",
    },
    checkAuthentication
  );
  assert.deepEqual(
    Object.fromEntries(report.routes.map((r) => [r.route, r.protectedBy])),
    {
      "/admin/stats": "a Sinatra before filter on /admin/*",
      "/accounts/:id": "a Sinatra before filter on /accounts/:id",
      "/accounts/:id/export": null,
      "/reports": null,
    }
  );
});

test("ruby: a before filter's evidence is its own block, not the route below it", () => {
  const report = run(
    {
      "app.rb":
        "require 'sinatra'\n\nbefore do\n  content_type :json\nend\n\n" +
        "post '/token' do\n  halt 401 unless params[:password]\nend\n\nget '/reports' do\n  '[]'\nend\n",
    },
    checkAuthentication
  );
  assert.equal(report.routes.find((r) => r.route === "/reports").protectedBy, null);
});

test("ruby: a before filter with a regular expression or a condition protects nothing here", () => {
  const report = run(
    {
      "app.rb":
        "require 'sinatra'\n\nbefore %r{/admin/.*} do\n  halt 401 unless session[:admin]\nend\n\n" +
        "before agent: /Bot/ do\n  halt 401\nend\n\nget '/admin/stats' do\n  'stats'\nend\n",
    },
    checkAuthentication
  );
  assert.equal(report.routes[0].protectedBy, null);
});

test("ruby: an unscoped before filter that refuses still protects every route", () => {
  const report = run(
    { "app.rb": "require 'sinatra'\n\nbefore do\n  halt 401 unless session[:user_id]\nend\n\nget '/reports' do\n  '[]'\nend\n" },
    checkAuthentication
  );
  assert.equal(report.routes[0].protectedBy, "a Sinatra before filter");
});

// Anchored to the start of a line so a method call inside a body is not read as a declaration.
test("ruby: a get call inside a body is not a route declaration", () => {
  const report = run(
    { "app.rb": "def fetch\n  response = client.get '/upstream' do |r|\n  end\nend\n" },
    checkAuthentication
  );
  assert.equal(report.routes.length, 0);
});

// ---------------------------------------------------------------------------------------------
// C# (ASP.NET Core). Each shape below is one measured on dvcsharp-api, Jellyfin, eShop or
// Bitwarden; the comment names which.
// ---------------------------------------------------------------------------------------------

const routesOf = (report) =>
  Object.fromEntries(report.routes.map((r) => [`${r.method} ${r.route}`, r.protectedBy || (r.anonymous ? "ANONYMOUS" : null)]));

test("c#: a controller action without [Authorize] fails, under its class route", () => {
  const { failures } = run(
    {
      "Controllers/ProductsController.cs":
        'namespace App.Controllers\n{\n   [Route("api/[controller]")]\n   public class ProductsController : Controller\n   {\n' +
        '      [HttpGet]\n      public IActionResult Get() { return Ok(); }\n\n' +
        '      [HttpPost("import")]\n      public IActionResult Import([FromBody] string xml) { return Ok(); }\n   }\n}\n',
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /2 of 2 endpoint\(s\)/);
  assert.match(failures[0], /GET \/api\/Products \(Controllers\/ProductsController\.cs:6\)/);
  assert.match(failures[0], /POST \/api\/Products\/import/);
  assert.match(failures[0], /\[Authorize\]/, "the advice names the C# idiom");
});

test("c#: [Authorize] on the class or the action protects; [AllowAnonymous] on the action overrides it", () => {
  const report = run(
    {
      "PluginsController.cs":
        '[Authorize]\n[Route("[controller]")]\npublic class PluginsController : ControllerBase\n{\n' +
        '    [HttpGet]\n    public ActionResult List() => Ok();\n' +
        '    [HttpGet("{id}/Image")]\n    [AllowAnonymous]\n    public ActionResult Image(Guid id) => Ok();\n}\n',
      "UsersController.cs":
        '[Route("api/users")]\npublic class UsersController : Controller\n{\n' +
        '    [Authorize(Policy = Policies.RequiresElevation)]\n    [HttpDelete("{id}")]\n    public IActionResult Delete(int id) => Ok();\n' +
        '    [HttpGet("{id}")]\n    public IActionResult Get(int id) => Ok();\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /Plugins": "an [Authorize] attribute",
    "GET /Plugins/{id}/Image": "ANONYMOUS",
    "DELETE /api/users/{id}": "an [Authorize] attribute",
    "GET /api/users/{id}": null,
  });
});

// Jellyfin: every controller derives from one base that carries [ApiController] and
// [Route("[controller]")]. Without the project indexed, every prefix was lost.
test("c#: the route prefix and [Authorize] are inherited from a base class in another file", () => {
  const report = run(
    {
      "Api/BaseApiController.cs": '[ApiController]\n[Route("[controller]")]\npublic class BaseApiController : ControllerBase\n{\n}\n',
      "Api/SecureBase.cs": "[Authorize]\npublic abstract class SecureBase : BaseApiController\n{\n}\n",
      "Api/Controllers/AudioController.cs":
        'public class AudioController : BaseApiController\n{\n    [HttpGet("{itemId}/stream")]\n    [HttpHead("{itemId}/stream")]\n    public ActionResult Stream(Guid itemId) => Ok();\n}\n',
      "Api/Controllers/ItemsController.cs":
        'public class ItemsController : SecureBase\n{\n    [HttpPost("{id}")]\n    public ActionResult Update(Guid id) => Ok();\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /Audio/{itemId}/stream": null,
    "HEAD /Audio/{itemId}/stream": null,
    "POST /Items/{id}": "an [Authorize] attribute",
  });
});

test("c#: an attribute class that authorizes counts; one that only validates does not", () => {
  const report = run(
    {
      "Auth/AdminOnlyAttribute.cs": "public class AdminOnlyAttribute : AuthorizeAttribute\n{\n    public AdminOnlyAttribute() { Roles = \"admin\"; }\n}\n",
      // Bitwarden's [InjectProvider]: an action filter that answers 401 to a non-admin.
      "Auth/InjectProviderAttribute.cs":
        "public class InjectProviderAttribute : ActionFilterAttribute\n{\n    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)\n    {\n" +
        '        if (!await IsAdmin(context))\n        {\n            context.Result = new UnauthorizedObjectResult(new ErrorResponseModel("Unauthorized."));\n            return;\n        }\n        await next();\n    }\n}\n',
      // Bitwarden's [SelfHosted]: a 400/404 gate on the environment, not on the caller.
      "Auth/SelfHostedAttribute.cs":
        "public class SelfHostedAttribute : ActionFilterAttribute\n{\n    public override void OnActionExecuting(ActionExecutingContext context)\n    {\n        context.Result = new BadRequestResult();\n    }\n}\n",
      // Bitwarden's [NoopAuthorize] documents a choice and enforces nothing.
      "Auth/NoopAuthorizeAttribute.cs": "public class NoopAuthorizeAttribute : Attribute;\n",
      "BillingController.cs":
        '[Route("billing")]\npublic class BillingController : Controller\n{\n' +
        '    [HttpGet("a")]\n    [AdminOnly]\n    public IActionResult A() => Ok();\n' +
        '    [HttpGet("b")]\n    [InjectProvider(ProviderUserType.ProviderAdmin)]\n    public IActionResult B() => Ok();\n' +
        '    [HttpGet("c")]\n    [SelfHosted(NotSelfHostedOnly = true)]\n    public IActionResult C() => Ok();\n' +
        '    [HttpGet("d")]\n    [NoopAuthorize]\n    public IActionResult D() => Ok();\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /billing/a": "an [AdminOnly] attribute",
    "GET /billing/b": "an [InjectProvider] attribute",
    "GET /billing/c": null,
    "GET /billing/d": null,
  });
});

test("c#: a fallback policy protects everything without [AllowAnonymous]; a default policy and UseAuthorization do not", () => {
  const controller =
    '[Route("api/logs")]\npublic class LogsController : Controller\n{\n    [HttpPost]\n    public IActionResult Create() => Ok();\n' +
    '    [HttpGet("public")]\n    [AllowAnonymous]\n    public IActionResult Public() => Ok();\n}\n';
  const minimal = 'app.MapGet("/api/items", () => Results.Ok());\n';
  const fallback = run(
    {
      "LogsController.cs": controller,
      "Program.cs":
        "builder.Services.AddAuthorization(options =>\n{\n    options.FallbackPolicy = new AuthorizationPolicyBuilder()\n        .RequireAuthenticatedUser()\n        .Build();\n});\n" + minimal,
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(fallback), {
    "POST /api/logs": "a fallback authorization policy requiring an authenticated user",
    "GET /api/logs/public": "ANONYMOUS",
    "GET /api/items": "a fallback authorization policy requiring an authenticated user",
  });
  // Jellyfin sets a DefaultPolicy, which only applies where [Authorize] already is.
  const notGlobal = run(
    {
      "LogsController.cs": controller,
      "Program.cs":
        "builder.Services.AddAuthorization(options =>\n{\n    options.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();\n});\n" +
        "app.UseAuthentication();\napp.UseAuthorization();\n" + minimal,
    },
    checkAuthentication
  );
  assert.equal(notGlobal.routes.filter((r) => r.protectedBy).length, 0);
});

test("c#: MapControllers().RequireAuthorization() and a global AuthorizeFilter protect controllers, not minimal APIs", () => {
  for (const setup of [
    "app.MapControllers().RequireAuthorization();\n",
    "builder.Services.AddControllers(o => o.Filters.Add(new AuthorizeFilter()));\n",
  ]) {
    const report = run(
      {
        "LogsController.cs": '[Route("api/logs")]\npublic class LogsController : Controller\n{\n    [HttpPost]\n    public IActionResult Create() => Ok();\n}\n',
        "Program.cs": setup + 'app.MapGet("/api/items", () => Results.Ok());\n',
      },
      checkAuthentication
    );
    assert.deepEqual(routesOf(report), { "POST /api/logs": "authorization required on every controller", "GET /api/items": null }, setup);
  }
});

test("c#: a controller with no route attributes is read as conventionally routed", () => {
  const report = run(
    {
      "AccountController.cs":
        "[AllowAnonymous]\npublic class AccountController : Controller\n{\n    [HttpGet]\n    public async Task<IActionResult> LoginAsync(string returnUrl) => View();\n}\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), { "GET /Account/Login": "ANONYMOUS" });
});

test("c#: minimal APIs -- RequireAuthorization on the endpoint, on the group, or as a statement on the group", () => {
  const report = run(
    {
      "Program.cs":
        'app.MapGet("/open", () => "x");\n' +
        'app.MapPost("/chained", (Item i) => Results.Ok()).RequireAuthorization();\n' +
        'var api = app.MapGroup("/api").RequireAuthorization("Application");\n' +
        'api.MapPut("/items/{id}", (int id) => Results.Ok());\n' +
        'api.MapGet("/status", () => "ok").AllowAnonymous();\n' +
        'var admin = app.MapGroup("/admin");\n' +
        'admin.WithTags("Admin");\n' +
        'admin.RequireAuthorization(Policies.Admin);\n' +
        'admin.MapDelete("/users/{id}", (int id) => Results.NoContent());\n' +
        'app.MapGet("/attr", [Authorize] (ClaimsPrincipal user) => user.Identity.Name);\n' +
        'app.MapMethods("/check", [HttpMethods.Options], () => Results.Ok());\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /open": null,
    "POST /chained": "RequireAuthorization() on the endpoint",
    "PUT /api/items/{id}": "RequireAuthorization() on its group",
    "GET /api/status": "ANONYMOUS",
    "DELETE /admin/users/{id}": "RequireAuthorization() on its group",
    "GET /attr": "an [Authorize] attribute on the handler",
    "OPTIONS /check": null,
  });
});

// eShop: the method that maps the routes returns its group, and the caller protects it.
test("c#: RequireAuthorization at the call site of a method that returns the group", () => {
  const ordersApi =
    "public static class OrdersApi\n{\n    public static RouteGroupBuilder MapOrdersApiV1(this IEndpointRouteBuilder app)\n    {\n" +
    '        var api = app.MapGroup("api/orders").HasApiVersion(1.0);\n        api.MapPut("/cancel", CancelOrderAsync);\n        api.MapGet("{orderId:int}", GetOrderAsync);\n        return api;\n    }\n}\n';
  const catalogApi =
    "public static class CatalogApi\n{\n    public static IEndpointRouteBuilder MapCatalogApi(this IEndpointRouteBuilder app)\n    {\n" +
    '        var api = app.MapGroup("api/catalog");\n        api.MapDelete("/items/{id:int}", DeleteItemById);\n        return app;\n    }\n}\n';
  const report = run(
    {
      "Ordering/Apis/OrdersApi.cs": ordersApi,
      "Ordering/Program.cs": 'var orders = app.NewVersionedApi("Orders");\n\norders.MapOrdersApiV1()\n      .RequireAuthorization();\n',
      "Catalog/Apis/CatalogApi.cs": catalogApi,
      "Catalog/Program.cs": "app.MapCatalogApi();\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "PUT /api/orders/cancel": "RequireAuthorization() on the call to MapOrdersApiV1()",
    "GET /api/orders/{orderId:int}": "RequireAuthorization() on the call to MapOrdersApiV1()",
    "DELETE /api/catalog/items/{id:int}": null,
  });
});

// Found while writing the reader: `app.MapOrdersApi().RequireAuthorization()` was read as a
// convention on `app`, which would have passed every other route mapped on app.
test("c#: RequireAuthorization on what a mapping call returns does not protect its receiver", () => {
  const report = run(
    {
      "OrdersApi.cs":
        "public static class OrdersApi\n{\n    public static RouteGroupBuilder MapOrdersApi(this IEndpointRouteBuilder app)\n    {\n" +
        '        var api = app.MapGroup("api/orders");\n        api.MapPost("/", Create);\n        return api;\n    }\n}\n',
      "Program.cs": 'app.MapOrdersApi().RequireAuthorization();\napp.MapPost("/api/admin/reset", () => Results.Ok());\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "POST /api/orders": "RequireAuthorization() on the call to MapOrdersApi()",
    "POST /api/admin/reset": null,
  });
});

test("c#: a route is protected only if every call site of its mapping method is", () => {
  const report = run(
    {
      "LeaseEndpoints.cs":
        "public static class LeaseEndpoints\n{\n    public static RouteGroupBuilder MapLeaseEndpoints(this RouteGroupBuilder group)\n    {\n" +
        '        group.MapPost("{id:guid}/revoke", (Guid id) => Results.NoContent());\n        return group;\n    }\n}\n',
      "Program.cs":
        'app.MapGroup("/leases").RequireAuthorization().MapLeaseEndpoints();\napp.MapGroup("/legacy/leases").MapLeaseEndpoints();\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), { "POST /leases/{id:guid}/revoke": null });
});

// Bitwarden: WithPamDefaults() delegates to an overload that calls group.RequireAuthorization(policy).
test("c#: a project helper that requires authorization on its group counts, through an overload", () => {
  const extensions =
    "public static class PamEndpointsExtensions\n{\n    public static void MapPamEndpoints(this IEndpointRouteBuilder endpoints)\n    {\n" +
    '        endpoints.MapGroup("/leases").WithPamDefaults().MapLeaseEndpoints();\n        endpoints.MapGroup("/open").WithTagsOnly().MapLeaseEndpoints2();\n    }\n\n' +
    "    private static RouteGroupBuilder WithPamDefaults(this RouteGroupBuilder group) =>\n        group.WithPamDefaults(Policies.Application, FeatureFlagKeys.Pam);\n\n" +
    "    private static RouteGroupBuilder WithPamDefaults(this RouteGroupBuilder group, string policy, string flag)\n    {\n" +
    "        group.RequireAuthorization(policy);\n        group.RequireFeature(flag);\n        return group;\n    }\n\n" +
    '    private static RouteGroupBuilder WithTagsOnly(this RouteGroupBuilder group)\n    {\n        group.WithTags("x");\n        return group;\n    }\n}\n';
  const leases =
    "internal static class LeaseEndpoints\n{\n    public static RouteGroupBuilder MapLeaseEndpoints(this RouteGroupBuilder group)\n    {\n" +
    '        group.MapGet("active", (ClaimsPrincipal user) => Results.Ok());\n        return group;\n    }\n\n' +
    "    public static RouteGroupBuilder MapLeaseEndpoints2(this RouteGroupBuilder group)\n    {\n" +
    '        group.MapGet("all", () => Results.Ok());\n        return group;\n    }\n}\n';
  const report = run({ "Pam/PamEndpointsExtensions.cs": extensions, "Pam/LeaseEndpoints.cs": leases }, checkAuthentication);
  assert.deepEqual(routesOf(report), {
    "GET /leases/active": "WithPamDefaults() on its group, which requires authorization",
    "GET /open/all": null,
  });
});

test("c#: [Authorize] in a comment or a string is not protection", () => {
  const report = run(
    {
      "LogsController.cs":
        '[Route("api/logs")]\npublic class LogsController : Controller\n{\n' +
        '    // [Authorize]\n    [HttpPost]\n    public IActionResult Create() => Ok();\n' +
        '    /* [Authorize] */ [HttpGet]\n    public IActionResult List() => Ok("[Authorize]");\n' +
        '    [HttpGet("{id}")]\n    public IActionResult Get(int id) { var s = "}"; return Ok(s); }\n' +
        '    [HttpDelete("{id}")]\n    public IActionResult Delete(int id) => Ok();\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "POST /api/logs": null,
    "GET /api/logs": null,
    "GET /api/logs/{id}": null,
    "DELETE /api/logs/{id}": null,
  }, "a brace inside a string does not end the class early either");
});

test("c#: test projects and test files are not the service", () => {
  const report = run(
    {
      "src/Api/LogsController.cs": '[Authorize]\n[Route("logs")]\npublic class LogsController : Controller\n{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n',
      "tests/Api.Integration.Tests/Controllers/EncoderController.cs":
        '[Route("enc")]\npublic class EncoderController : Controller\n{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n',
      "test/Api.Test/FakeController.cs": '[Route("fake")]\npublic class FakeController : Controller\n{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n',
      "src/Api/LogsControllerTests.cs": '[Route("t")]\npublic class T : Controller\n{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), { "GET /logs": "an [Authorize] attribute" });
});

test("c#: a probe and a credential-issuing route are exempt, as in every language", () => {
  const report = run(
    { "Program.cs": 'app.MapGet("/health", () => "ok");\napp.MapPost("/api/login", (Login l) => Results.Ok());\napp.MapPost("/health", () => Purge());\n' },
    checkAuthentication
  );
  assert.deepEqual(report.exempt.map((e) => `${e.method} ${e.route}`), ["GET /health", "POST /api/login"]);
  assert.deepEqual(routesOf(report), { "POST /health": null });
});

test("c#: an open route declared anonymous says so in the finding", () => {
  const { failures } = run(
    { "Program.cs": 'app.MapPost("/api/items", (Item i) => Results.Ok()).AllowAnonymous();\n' },
    authenticationFailures
  );
  assert.match(failures[0], /POST \/api\/items \(Program\.cs:1, declared anonymous\)/);
});

test("c#: a credential compared with == is reported, with the C# constant-time call as the fix", () => {
  const { failures } = run(
    {
      "Endpoints.cs":
        'var tokenToValidate = configuration["WebhookClientOptions:Token"];\n' +
        'app.MapPost("/webhook-received", (WebhookData hook, HttpRequest request) =>\n{\n    var token = request.Headers["X-eshop-whtoken"];\n' +
        "    if (tokenToValidate == token) { return Results.Ok(); }\n    return Results.BadRequest();\n}).RequireAuthorization();\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /`tokenToValidate` is compared with an ordinary equality operator/);
  assert.match(failures[0], /CryptographicOperations\.FixedTimeEquals/);
});

// Each of these was reported as a credential compared unsafely when the C# reader was first run on
// dvcsharp-api and Bitwarden. None compares a secret.
test("a name about a credential, a property of an object named for one, or a confirmation is not a credential", () => {
  for (const line of [
    "if (b.email == passwordResetRequest.email) {}",                 // dvcsharp: the receiver's name
    "if (password != passwordConfirmation) {}",                       // dvcsharp: the caller's input, twice
    "var s = q.Where(s => s.SecretId == secretId);",                  // Bitwarden: an id
    "if (apiKey.Id == apiKeyId) {}",
    "if (passwordResult == PasswordVerificationResult.Failed) {}",  // Bitwarden: a result
    "return Identifier == TokenIdentifier;",                          // Bitwarden: a constant name
    "if (useResetPassword == organization.UseResetPassword) {}",      // Bitwarden: a flag
    "if (secretsManagerSeatQuantity != seats) {}",                    // Bitwarden: a count
    "if (token_type == expected_type) {}",
  ]) {
    assert.equal(leakyCredentialCheck(line), false, line);
  }
  // Still credentials: the value itself, and a method called on it.
  assert.equal(leakyCredentialCheck("if (apiKey == expected) {}"), "apiKey");
  assert.equal(leakyCredentialCheck("if (req.apiToken == provided) {}"), "apiToken");
  assert.equal(leakyCredentialCheck("if (provided == apiToken.Trim()) {}"), "apiToken");
  assert.equal(leakyCredentialCheck("if (req.headers.token === provided) {}"), "token");
});

// ---------------------------------------------------------------------------------------------
// PHP: Laravel and Symfony. Shapes measured on BookStack, Symfony demo and DVWA.
// ---------------------------------------------------------------------------------------------

// BookStack's Kernel, cut down: 'auth' is the project's own class, which answers 401; 'api' is a
// group whose ApiAuthenticate throws a 403; 'guard' only checks configuration and redirects home.
const LARAVEL_KERNEL =
  "<?php\nnamespace App\\Http;\n\nclass Kernel extends HttpKernel\n{\n" +
  "    protected $middlewareGroups = [\n        'web' => [\n            \\App\\Http\\Middleware\\EncryptCookies::class,\n        ],\n" +
  "        'api' => [\n            \\App\\Http\\Middleware\\ThrottleApiRequests::class,\n            \\App\\Http\\Middleware\\ApiAuthenticate::class,\n        ],\n    ];\n" +
  "    protected $middlewareAliases = [\n        'auth'  => \\App\\Http\\Middleware\\Authenticate::class,\n        'guest' => \\App\\Http\\Middleware\\RedirectIfAuthenticated::class,\n" +
  "        'guard' => \\App\\Http\\Middleware\\CheckGuard::class,\n    ];\n}\n";
const LARAVEL_MIDDLEWARE = {
  "app/Http/Middleware/Authenticate.php":
    "<?php\nclass Authenticate\n{\n    public function handle(Request $request, Closure $next)\n    {\n        if (!user()->hasAppAccess()) {\n" +
    "            return response('Unauthorized.', 401);\n        }\n        return $next($request);\n    }\n}\n",
  "app/Http/Middleware/ApiAuthenticate.php":
    "<?php\nclass ApiAuthenticate\n{\n    public function handle(Request $request, Closure $next)\n    {\n        if (!$this->valid($request)) {\n" +
    "            throw new ApiAuthException(trans('errors.api_no_token'), 403);\n        }\n        return $next($request);\n    }\n}\n",
  "app/Http/Middleware/CheckGuard.php":
    "<?php\nclass CheckGuard\n{\n    public function handle($request, Closure $next, ...$allowedGuards)\n    {\n        if (!in_array(config('auth.method'), $allowedGuards)) {\n" +
    "            return redirect('/');\n        }\n        return $next($request);\n    }\n}\n",
  "app/Http/Middleware/RedirectIfAuthenticated.php":
    "<?php\nclass RedirectIfAuthenticated\n{\n    public function handle(Request $request, Closure $next)\n    {\n        if (Auth::check()) {\n" +
    "            return redirect(RouteServiceProvider::HOME);\n        }\n        return $next($request);\n    }\n}\n",
};

test("php: Laravel middleware on the route, on a group, and through a group that includes the route file", () => {
  const report = run(
    {
      "app/Http/Kernel.php": LARAVEL_KERNEL,
      ...LARAVEL_MIDDLEWARE,
      "app/Providers/RouteServiceProvider.php":
        "<?php\nclass RouteServiceProvider extends ServiceProvider\n{\n    protected function mapApiRoutes(): void\n    {\n" +
        "        Route::group([\n            'middleware' => 'api',\n            'prefix'     => 'api',\n        ], function ($router) {\n" +
        "            require base_path('routes/api.php');\n        });\n" +
        "        Route::middleware('web')->group(base_path('routes/web.php'));\n    }\n}\n",
      "routes/api.php": "<?php\n\nRoute::get('pages', [PageApiController::class, 'list']);\nRoute::delete('pages/{id}', [PageApiController::class, 'delete']);\n",
      "routes/web.php":
        "<?php\n\nRoute::get('/status', [StatusController::class, 'show']);\n" +
        "Route::middleware('auth')->group(function () {\n    Route::get('/books', [BookController::class, 'index']);\n" +
        "    Route::prefix('settings')->group(function () {\n        Route::post('/{category}', [SettingController::class, 'update']);\n    });\n});\n" +
        "Route::delete('/mfa/{method}/remove', [MfaController::class, 'remove'])->middleware('auth');\n" +
        "Route::middleware('guest')->group(function () {\n    Route::get('/mfa/verify', [MfaController::class, 'verify']);\n});\n" +
        "Route::get('/saml2/metadata', [Saml2Controller::class, 'metadata'])->middleware('guard:saml2');\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /api/pages": "the ApiAuthenticate middleware, in the 'api' middleware group",
    "DELETE /api/pages/{id}": "the ApiAuthenticate middleware, in the 'api' middleware group",
    "GET /status": null,
    "GET /books": "the 'auth' middleware",
    "POST /settings/{category}": "the 'auth' middleware",
    "DELETE /mfa/{method}/remove": "the 'auth' middleware",
    "GET /mfa/verify": null,
    "GET /saml2/metadata": null,
  });
});

test("php: Laravel's own aliases count when the project does not redefine them; withoutMiddleware takes one away", () => {
  const report = run(
    {
      "routes/web.php":
        "<?php\nRoute::middleware(['auth:sanctum', 'verified'])->group(function () {\n" +
        "    Route::get('/dashboard', fn () => view('dashboard'));\n" +
        "    Route::post('/hooks/stripe', [StripeController::class, 'handle'])->withoutMiddleware(['auth:sanctum', 'verified']);\n" +
        "    Route::get('/feed', fn () => view('feed'))->withoutMiddleware(['auth:sanctum', 'verified']);\n});\n" +
        "Route::get('/reports', [ReportController::class, 'index'])->middleware('can:view-reports');\n" +
        "Route::get('/unsubscribe/{user}', [MailController::class, 'unsubscribe'])->middleware('signed');\n" +
        "Route::get('/about', fn () => view('about'))->middleware('throttle:60,1');\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /dashboard": "the 'auth:sanctum' middleware",
    "POST /hooks/stripe": null,
    "GET /feed": null,
    "GET /reports": "the 'can:view-reports' middleware",
    "GET /unsubscribe/{user}": "the 'signed' middleware",
    "GET /about": null,
  });
});

test("php: a controller's constructor middleware, with except and only", () => {
  const report = run(
    {
      "app/Http/Controllers/PostController.php":
        "<?php\nclass PostController extends Controller\n{\n    public function __construct()\n    {\n" +
        "        $this->middleware('auth')->except(['index', 'show']);\n    }\n" +
        "    public function index() {}\n    public function show($id) {}\n    public function store() {}\n}\n",
      "app/Http/Controllers/AdminController.php":
        "<?php\nclass AdminController extends Controller\n{\n    public function __construct()\n    {\n" +
        "        $this->middleware('auth', ['only' => ['purge']]);\n    }\n}\n",
      "routes/web.php":
        "<?php\nRoute::resource('posts', PostController::class)->only(['index', 'show', 'store']);\n" +
        "Route::post('/admin/purge', [AdminController::class, 'purge']);\nRoute::get('/admin/stats', 'AdminController@stats');\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /posts": null,
    "GET /posts/{id}": null,
    "POST /posts": "the 'auth' middleware",
    "POST /admin/purge": "the 'auth' middleware",
    "GET /admin/stats": null,
  });
});

test("php: Laravel 11's bootstrap/app.php -- withRouting, a middleware alias and a group", () => {
  const report = run(
    {
      "bootstrap/app.php":
        "<?php\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(\n        web: __DIR__.'/../routes/web.php',\n" +
        "        api: __DIR__.'/../routes/api.php',\n    )\n    ->withMiddleware(function (Middleware $middleware) {\n" +
        "        $middleware->alias([\n            'admin' => EnsureAdmin::class,\n        ]);\n" +
        "        $middleware->appendToGroup('api', [ApiToken::class]);\n    })\n    ->create();\n",
      "app/Http/Middleware/EnsureAdmin.php":
        "<?php\nclass EnsureAdmin\n{\n    public function handle($request, $next)\n    {\n        abort_unless($request->user()?->isAdmin(), 403);\n        return $next($request);\n    }\n}\n",
      "app/Http/Middleware/ApiToken.php":
        "<?php\nclass ApiToken\n{\n    public function handle($request, $next)\n    {\n        if (!$request->bearerToken()) {\n            throw new AuthenticationException();\n        }\n        return $next($request);\n    }\n}\n",
      "routes/web.php": "<?php\nRoute::get('/admin', [AdminController::class, 'index'])->middleware('admin');\nRoute::get('/', fn () => view('welcome'));\n",
      "routes/api.php": "<?php\nRoute::post('/orders', [OrderController::class, 'store']);\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /admin": "the 'admin' middleware",
    "GET /": null,
    "POST /api/orders": "the ApiToken middleware, in the 'api' middleware group",
  });
});

test("php: Symfony -- #[IsGranted] on the class or the action, denyAccessUnlessGranted, and access_control", () => {
  const report = run(
    {
      "src/Controller/Admin/BlogController.php":
        "<?php\n#[Route('/admin/post')]\n#[IsGranted(User::ROLE_ADMIN)]\nfinal class BlogController extends AbstractController\n{\n" +
        "    #[Route('/', name: 'admin_index', methods: ['GET'])]\n    public function index(): Response {}\n" +
        "    #[Route('/{id:post}/delete', name: 'admin_post_delete', methods: ['POST'])]\n    public function delete(Post $post): Response {}\n}\n",
      "src/Controller/BlogController.php":
        "<?php\n#[Route('/blog')]\nfinal class BlogController extends AbstractController\n{\n" +
        "    #[Route('/', name: 'blog_index', methods: ['GET'])]\n    public function index(): Response {}\n" +
        "    #[Route('/comment/{postSlug}/new', name: 'comment_new', methods: ['POST'])]\n    #[IsGranted('IS_AUTHENTICATED')]\n    public function commentNew(): Response {}\n" +
        "    #[Route('/drafts', methods: ['GET'])]\n    public function drafts(): Response\n    {\n        $this->denyAccessUnlessGranted('ROLE_USER');\n        return new Response('');\n    }\n" +
        "    #[Route('/feed', methods: ['GET'])]\n    #[IsGranted('PUBLIC_ACCESS')]\n    public function feed(): Response {}\n}\n",
      "src/Controller/ApiController.php":
        "<?php\nclass ApiController extends AbstractController\n{\n    #[Route('/api/export', methods: ['GET', 'POST'])]\n    public function export(): Response {}\n" +
        "    #[Route('/api/public/status')]\n    public function status(): Response {}\n}\n",
      "config/packages/security.yaml":
        "security:\n    firewalls:\n        main:\n            lazy: true\n    access_control:\n" +
        "        - { path: ^/api/public, roles: PUBLIC_ACCESS }\n        - { path: ^/api, roles: ROLE_API }\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /admin/post": "an #[IsGranted] attribute on the controller",
    "POST /admin/post/{id:post}/delete": "an #[IsGranted] attribute on the controller",
    "GET /blog": null,
    "POST /blog/comment/{postSlug}/new": "an #[IsGranted] attribute",
    "GET /blog/drafts": "denyAccessUnlessGranted() in the action",
    "GET /blog/feed": null,
    "ANY /api/export": "an access_control rule requiring ROLE_API",
    "ANY /api/public/status": null,
  });
});

test("php: routes in comments, strings, Blade views and plain PHP pages are not read", () => {
  const report = run(
    {
      "routes/web.php":
        "<?php\n// Route::get('/old', [OldController::class, 'index']);\n# Route::get('/older', fn () => 1);\n" +
        "/* Route::post('/oldest', fn () => 1); */\n$doc = \"Route::get('/in-a-string', fn () => 1);\";\nRoute::get('/real', fn () => 1);\n",
      "resources/views/welcome.blade.php": "<?php Route::get('/from-a-view', fn () => 1); ?>\n<p>it's here</p>\n",
      "vulnerabilities/exec/index.php": "<?php\nrequire_once '../../dvwa/includes/dvwaPage.inc.php';\ndvwaPageStartup( array( 'authenticated' ) );\n",
      "tests/Feature/RoutesTest.php": "<?php\nRoute::get('/test-only', fn () => 1);\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), { "GET /real": null });
});

// ---------------------------------------------------------------------------------------------
// Kotlin: Spring and Ktor. Shapes measured on spring-petclinic-kotlin, kotlin-spring-realworld,
// kotlin-ktor-realworld and ktor-samples.
// ---------------------------------------------------------------------------------------------

test("kotlin: Spring mappings, Kotlin array syntax and a class prefix; @PreAuthorize protects", () => {
  const report = run(
    {
      "src/main/kotlin/owner/PetController.kt":
        '@Controller\n@RequestMapping("/owners/{ownerId}")\nclass PetController(val owners: OwnerRepository) {\n\n' +
        '    @GetMapping("/pets/new")\n    fun initCreationForm(owner: Owner, model: Model): String = VIEW\n\n' +
        '    @PostMapping(value = ["/pets/{petId}/edit", "/pets/{petId}/update"])\n    @PreAuthorize("hasRole(\'OWNER\')")\n    fun processUpdateForm(pet: Pet): String {\n        return "redirect:/owners/{ownerId}"\n    }\n\n' +
        '    @RequestMapping("/pets/{petId}/visits", method = [RequestMethod.POST])\n    @PreAuthorize("permitAll()")\n    fun addVisit(): String = "x"\n}\n',
      "src/main/kotlin/vet/VetController.kt": '@RestController\nclass VetController {\n    @GetMapping("vets.json", produces = ["application/json"])\n    fun showResources(): Vets = Vets()\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /owners/{ownerId}/pets/new": null,
    "POST /owners/{ownerId}/pets/{petId}/edit": "a @PreAuthorize annotation",
    "POST /owners/{ownerId}/pets/{petId}/update": "a @PreAuthorize annotation",
    "POST /owners/{ownerId}/pets/{petId}/visits": null,
    "GET /vets.json": null,
  });
});

// kotlin-spring-realworld: @ApiKeySecured, enforced by an aspect that answers 401.
test("kotlin: an annotation an aspect enforces with 401 protects, unless the use switches it off", () => {
  const report = run(
    {
      "src/main/kotlin/jwt/ApiKeySecured.kt":
        "@Retention(AnnotationRetention.RUNTIME)\n@Target(AnnotationTarget.FUNCTION)\nannotation class ApiKeySecured(val mandatory: Boolean = true)\n",
      "src/main/kotlin/jwt/ApiKeySecuredAspect.kt":
        "@Aspect\n@Component\nclass ApiKeySecuredAspect(val userService: UserService) {\n" +
        '    @Pointcut(value = "execution(@io.realworld.jwt.ApiKeySecured * *.*(..))")\n    fun securedApiPointcut() {\n    }\n\n' +
        '    @Around("securedApiPointcut()")\n    fun around(joinPoint: ProceedingJoinPoint): Any? {\n' +
        "        if (request.getHeader(\"Authorization\") == null) {\n            response.status = HttpServletResponse.SC_UNAUTHORIZED\n            return null\n        }\n        return joinPoint.proceed()\n    }\n}\n",
      "src/main/kotlin/jwt/Audited.kt": "annotation class Audited\n",
      "src/main/kotlin/jwt/AuditAspect.kt":
        '@Aspect\nclass AuditAspect {\n    @Before("@annotation(io.realworld.jwt.Audited)")\n    fun log() { println("x") }\n}\n',
      "src/main/kotlin/web/ArticleHandler.kt":
        "@RestController\nclass ArticleHandler(val repository: ArticleRepository) {\n" +
        '    @ApiKeySecured(mandatory = false)\n    @GetMapping("/api/articles")\n    fun articles(): Any = repository.findAll()\n\n' +
        '    @ApiKeySecured\n    @PostMapping("/api/articles")\n    fun newArticle(): Any = 1\n\n' +
        '    @Audited\n    @DeleteMapping("/api/articles/{slug}")\n    fun deleteArticle(): Any = 1\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "GET /api/articles": null,
    "POST /api/articles": "@ApiKeySecured, which an aspect enforces",
    "DELETE /api/articles/{slug}": null,
  });
});

test("kotlin: Spring security rules are taken in order, so permitAll before anyRequest stays open", () => {
  const controller =
    '@RestController\nclass Api {\n    @GetMapping("/api/public/tags")\n    fun tags() = 1\n    @PostMapping("/api/articles")\n    fun create() = 1\n' +
    '    @GetMapping("/api/articles/{slug}")\n    fun read() = 1\n}\n';
  for (const config of [
    // the Kotlin DSL
    "@Bean\nfun filterChain(http: HttpSecurity): SecurityFilterChain {\n    http {\n        authorizeHttpRequests {\n" +
      '            authorize("/api/public/**", permitAll)\n            authorize(HttpMethod.GET, "/api/articles/**", permitAll)\n            authorize(anyRequest, authenticated)\n        }\n    }\n    return http.build()\n}\n',
    // the lambda style
    "@Bean\nfun filterChain(http: HttpSecurity): SecurityFilterChain = http\n    .authorizeHttpRequests {\n" +
      '        it.requestMatchers("/api/public/**").permitAll()\n            .requestMatchers(HttpMethod.GET, "/api/articles/**").permitAll()\n            .anyRequest().authenticated()\n    }\n    .build()\n',
  ]) {
    const report = run({ "src/main/kotlin/Api.kt": controller, "src/main/kotlin/SecurityConfig.kt": "@Configuration\nclass SecurityConfig {\n" + config + "}\n" }, checkAuthentication);
    assert.deepEqual(routesOf(report), {
      "GET /api/public/tags": null,
      "POST /api/articles": "a security rule requiring authenticated",
      "GET /api/articles/{slug}": null,
    });
  }
});

// kotlin-ktor-realworld's Router.kt, cut down.
test("kotlin: Ktor nesting decides path and protection; optional inside required stays required", () => {
  const report = run(
    {
      "src/main/kotlin/web/Router.kt":
        'fun Routing.users(userController: UserController) {\n    route("users") {\n        post { userController.register(this.context) }\n' +
        '        post("login") { userController.login(this.context) }\n    }\n    route("user") {\n        authenticate {\n' +
        "            get { userController.getCurrent(this.context) }\n            put { userController.update(this.context) }\n        }\n    }\n}\n\n" +
        'fun Routing.articles(articleController: ArticleController) {\n    route("articles") {\n        authenticate {\n' +
        '            route("{slug}") {\n                authenticate(optional = true) {\n                    get { articleController.get(this.context) }\n                }\n' +
        "                delete { articleController.delete(this.context) }\n            }\n        }\n        authenticate(optional = true) {\n" +
        "            get { articleController.findBy(this.context) }\n        }\n    }\n}\n",
      "src/main/kotlin/config/AppConfig.kt": "fun Application.module() {\n    install(Routing) {\n        users(userController)\n        articles(articleController)\n    }\n}\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "POST /users": null,
    "POST /users/login": null,
    "GET /user": "an enclosing authenticate block",
    "PUT /user": "an enclosing authenticate block",
    "GET /articles/{slug}": "an enclosing authenticate block",
    "DELETE /articles/{slug}": "an enclosing authenticate block",
    "GET /articles": null,
  });
});

test("kotlin: a Ktor route function is judged at every call; one unprotected call opens it", () => {
  const routes =
    'fun Route.adminRoutes() {\n    post("purge") { call.respond(HttpStatusCode.NoContent) }\n}\n\n' +
    'fun Route.reportRoutes() {\n    get("reports") { call.respond("x") }\n}\n';
  const report = run(
    {
      "src/main/kotlin/Routes.kt": routes,
      "src/main/kotlin/Application.kt":
        'fun Application.module() {\n    routing {\n        authenticate("admin") {\n            route("admin") {\n                adminRoutes()\n            }\n' +
        "            reportRoutes()\n        }\n        reportRoutes()\n    }\n}\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), {
    "POST /admin/purge": "an enclosing authenticate block, around every call of adminRoutes()",
    "GET /reports": null,
  });
});

test("kotlin: typed Ktor routes take their path from @Resource; HTML builders and client calls are not routes", () => {
  const report = run(
    {
      "src/main/kotlin/Resources.kt": '@Resource("/video/{id}")\nclass VideoStream(val id: Long)\n\n@Resource("/login")\nclass Login(val userName: String = "")\n',
      "src/main/kotlin/Videos.kt":
        "fun Route.videos() {\n    get<VideoStream> {\n        call.respondHtml {\n            head { title(\"x\") }\n            body { p { +\"x\" } }\n        }\n    }\n" +
        "    resource<Login> {\n        authenticate(\"form\") {\n            post { call.respondRedirect(\"/\") }\n        }\n    }\n}\n",
      "src/main/kotlin/Client.kt": 'suspend fun fetch(client: HttpClient) {\n    val r = client.get("https://example.com/x") { header("A", "b") }\n}\n',
      "src/main/kotlin/Layout.kt": 'fun HTML.layout() {\n    head {\n        title("YouKube")\n    }\n}\n',
      "src/main/kotlin/App.kt": "fun Application.module() {\n    routing {\n        videos()\n    }\n}\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), { "GET /video/{id}": null });
  assert.deepEqual(report.exempt.map((e) => `${e.method} ${e.route}`), ["POST /login"]);
});

test("kotlin: the src/test source set is not the service", () => {
  const report = run(
    {
      "src/main/kotlin/App.kt": 'fun Application.module() {\n    routing {\n        authenticate {\n            get("/me") { call.respond("x") }\n        }\n    }\n}\n',
      "src/test/kotlin/TestModule.kt": 'fun Application.testModule() {\n    routing {\n        get("/debug") { call.respond("x") }\n    }\n}\n',
      "src/integrationTest/kotlin/Stub.kt": 'fun Application.stub() {\n    routing {\n        get("/stub") { call.respond("x") }\n    }\n}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(routesOf(report), { "GET /me": "an enclosing authenticate block" });
});

// Each was reported as a credential compared unsafely when the PHP reader was first run on BookStack.
test("a class constant, a token's claim and a constant flag are not credentials", () => {
  for (const line of [
    "if ($response === Password::RESET_LINK_SENT) {}",
    "return $response === Password::PASSWORD_RESET;",
    "if ($idTokenSub !== $sub) {}",
    "return self.__mode === IS_TOKEN;",                   // BookStack's editor: a mode flag
  ]) {
    assert.equal(leakyCredentialCheck(line), false, line);
  }
  assert.equal(leakyCredentialCheck("if ($user->password == $given) {}"), "password");
  assert.equal(leakyCredentialCheck("if (userFound?.password == encrypt(given)) {}"), "password");
});

// ---------------------------------------------------------------------------------------------
// Cross-cutting
// ---------------------------------------------------------------------------------------------

// Global auth is judged per language against that language's own files. A Python app-wide
// dependency says nothing about an Express server sitting beside it in the same repo.
test("one language's global auth does not protect another's routes", () => {
  const { failures } = run(
    {
      "api/main.py":
        "app = FastAPI(dependencies=[Depends(verify_api_key)])\n@app.get('/reports')\ndef read():\n    pass\n",
      "web/server.js": "app.post('/logs', create);\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/logs/);
  assert.doesNotMatch(failures[0], /\/reports/);
});

test("health probes are exempt in every language", () => {
  const { failures } = run(
    {
      "src/app.js": "app.get('/health', ok);\n",
      "main.go": 'r.Get("/healthz", ok)\n',
      "app.rb": "get '/ping' do\nend\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// The probe exemption had no terminal anchor, so anything under a probe path was exempt. Renaming an
// unauthenticated admin route to /health/purge-all took its finding away -- measured, 3 blocking to
// 2, with the exemption reported only as an advisory nobody in an unattended pipeline reads.
test("a probe is exempt by its name, not by being a prefix of the path", () => {
  for (const route of ["/health", "/healthz", "/readyz", "/ready", "/livez", "/live", "/ping", "/metrics", "/favicon.ico"]) {
    assert.ok(isProbeRoute(route), `${route} is a probe`);
  }
  for (const route of ["/health/purge-all", "/metrics/export-users", "/ping/admin/reset", "/health/:id", "/healthcheck-admin", "/metrics.json"]) {
    assert.equal(isProbeRoute(route), false, `${route} is under or beside a probe name, not a probe`);
  }
});

test("a trailing slash and a probe-named sub-path stay exempt; a written-out mount prefix is checked", () => {
  // Decided, not defaulted. /health/ is the same endpoint as /health in Express and Flask.
  // /health/live and /health/ready, the Kubernetes split, were exempt before and still are.
  for (const route of ["/health/", "/health/live", "/health/ready", "/healthz/readiness/", "/HEALTH"]) {
    assert.ok(isProbeRoute(route), route);
  }
  // Routes are read as written. A router mounted at /api declares plain /health and is exempt; a
  // path written out as /api/health was checked before this change, and exempting it would loosen
  // the gate rather than fix it.
  for (const route of ["/api/health", "/api/v1/healthz", "/admin/health"]) {
    assert.equal(isProbeRoute(route), false, route);
  }
});

test("an unauthenticated route nested under a probe path is a finding, in every language", () => {
  const { failures } = run(
    {
      "src/app.js": "app.post('/health/purge-all', purge);\n",
      "main.go": 'r.Post("/metrics/export-users", exportUsers)\n',
      "app.rb": "post '/ping/admin/reset' do\nend\n",
    },
    authenticationFailures
  );
  const said = failures.join("\n");
  assert.match(said, /\/health\/purge-all/);
  assert.match(said, /\/metrics\/export-users/);
  assert.match(said, /\/ping\/admin\/reset/);
});

// A probe reads. The exemption covered a probe path whatever the method, so POST /health running a
// DELETE passed the authentication check -- in both modes.
test("a write method on a probe path is checked, in every language", () => {
  const { failures } = run(
    {
      "src/app.js": "app.post('/health', purgeUsers);\n",
      "main.go": 'r.Delete("/healthz", dropAll)\n',
      "app.rb": "put '/ping' do\nend\n",
      "app/main.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/metrics', methods=['POST'])\ndef reset():\n    pass\n",
      "src/main/java/Probe.java":
        '@RestController\nclass Probe {\n  @RequestMapping(value = "/readyz", method = RequestMethod.DELETE)\n  void wipe() {}\n}\n',
    },
    authenticationFailures
  );
  const said = failures.join("\n");
  for (const route of ["POST /health", "DELETE /healthz", "PUT /ping", "/metrics", "/readyz"]) {
    assert.match(said, new RegExp(route.replace(/\//g, "\\/")), route);
  }
});

test("a read method, or a registration that names no method, is still exempt on a probe path", () => {
  // GET and HEAD, and the method-agnostic forms -- Go's HandleFunc, a bare Flask @app.route,
  // Express's app.all, Spring's @RequestMapping with no method -- which were exempt before: from the
  // source alone nothing says the handler writes.
  const { failures, advisories } = run(
    {
      "src/app.js": "app.get('/health', ok);\napp.all('/livez', ok);\n",
      "main.go": 'mux.HandleFunc("/healthz", ok)\n',
      "app/main.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ping')\ndef ping():\n    pass\n",
      "src/main/java/Probe.java": '@RestController\nclass Probe {\n  @RequestMapping("/readyz")\n  String ready() { return "ok"; }\n  @GetMapping("/metrics")\n  String m() { return ""; }\n}\n',
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
  assert.match(advisories.join("\n"), /exempt by name/);
});

// An endpoint whose job is to issue a credential cannot require one first.
test("credential-issuing endpoints are exempt, but paths beneath them are not", () => {
  const exempt = run({ "src/app.js": "app.post('/login', doLogin);\n" }, authenticationFailures);
  assert.deepEqual(exempt.failures, []);

  const notExempt = run({ "src/app.js": "app.get('/auth/admin/users', listUsers);\n" }, authenticationFailures);
  assert.equal(notExempt.failures.length, 1);
});

test("an unrecognised language is undetermined, not a pass", () => {
  const { failures, advisories } = run(
    { "src/main.rs": "let app = Router::new().route(\"/logs\", post(create));\n" },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
  assert.equal(advisories.length, 1);
  assert.match(advisories[0], /not checked/);
});

test("the remediation names the idiom of the language actually found", () => {
  const { failures } = run({ "src/app.js": "app.post('/logs', create);\n" }, authenticationFailures);
  assert.match(failures[0], /app\.use\(requireAuth\)|preHandler|UseGuards/);
  assert.doesNotMatch(failures[0], /FastAPI/);
});

// Found by running this check over its own repository: 15 phantom routes came from this very test
// file, whose fixtures quote route calls as strings. A phantom route carries no middleware, so it
// reports as unprotected, so it would block a project that is in fact correct.
test("route calls quoted inside a test file are not routes", () => {
  const report = run(
    {
      "src/app.js": "app.post('/logs', requireAuth, create);\n",
      "src/app.test.js": "it('rejects anonymous writes', () => {\n  const src = \"app.post('/logs', create);\";\n});\n",
      "src/handlers.spec.ts": "describe('x', () => { const s = \"app.get('/admin', list);\"; });\n",
    },
    checkAuthentication
  );
  assert.equal(report.routes.length, 1, "only the real route in src/app.js should count");
  assert.equal(report.routes[0].file, "src/app.js");
});

test("test files in other languages are skipped too", () => {
  const report = run(
    {
      "main_test.go": 'r.Post("/logs", createLog)\n',
      "test_api.py": "@app.post('/logs')\ndef add():\n    pass\n",
      "app_spec.rb": "post '/logs' do\nend\n",
    },
    checkAuthentication
  );
  assert.equal(report.routes.length, 0);
  assert.ok(report.unknown, "nothing to check is undetermined, not a pass");
});

// The scanner's own remediation text describes a route shape. If that text were written as a
// quoted path followed by a comma, the check would declare a route every time it explained one.
test("the remediation text does not itself parse as a route", () => {
  const report = run(
    { "src/doc.js": "const help = \"middleware on the route (app.post(path, requireAuth, handler))\";\n" },
    checkAuthentication
  );
  assert.equal(report.routes.length, 0);
});

// A webhook sender proves identity by signing the payload, not by presenting a bearer token. This
// check reported such an endpoint as unauthenticated on a real webhook receiver -- a false
// positive only a different task shape would surface, since every earlier run used API keys.
test("a verified request signature is authentication", () => {
  const { failures } = run(
    {
      "src/main.py":
        "import hmac, hashlib\n" +
        "def verify(body, sig):\n" +
        "    expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()\n" +
        "    return hmac.compare_digest(expected, sig)\n\n" +
        "@app.post('/webhook')\n" +
        "async def receive(request: Request, x_signature: str = Header(None)):\n" +
        "    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// The same discipline that keeps Depends(get_db) from counting: a header is not a control until
// something checks it.
test("a signature header with no verification anywhere is not authentication", () => {
  const { failures } = run(
    {
      "src/main.py":
        "@app.post('/webhook')\nasync def receive(x_signature: str = Header(None)):\n    return {'ok': True}\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/webhook/);
});

// Recognising a signature as authentication without this would leave the gate certifying a
// control with an exploitable timing leak, which is worse than not recognising it at all.
test("an equality-compared signature is reported even when every route is protected", () => {
  const leaky = {
    "src/main.py":
      "import hmac, hashlib\n" +
      "def verify(body, sig):\n" +
      "    expected_signature = hmac.new(S.encode(), body, hashlib.sha256).hexdigest()\n" +
      "    return expected_signature == sig\n\n" +
      "@app.post('/webhook')\n" +
      "async def receive(request: Request, x_signature: str = Header(None)):\n    pass\n",
  };
  const r = run(leaky, authenticationFailures);
  assert.equal(r.failures.length, 1, "no route is open, so this is the timing finding alone");
  assert.match(r.failures[0], /constant-time/);

  const fixed = {
    "src/main.py": leaky["src/main.py"].replace(
      "return expected_signature == sig",
      "return hmac.compare_digest(expected_signature, sig)"
    ),
  };
  assert.deepEqual(run(fixed, authenticationFailures).failures, [], "clears once compared safely");
});

// Found by hand-testing a webhook receiver that authenticated both routes, passed this gate, and
// still served every stored callback to an unauthenticated request: its Deployment never set
// SUPPORT_API_KEY, and `None != None` is false. The same file validated three other environment
// variables at startup and not these two.
test("a credential compared against an unset environment variable is a vacuous check", () => {
  const { failures } = run(
    {
      "src/main.py":
        "import os\n" +
        'SUPPORT_API_KEY = os.getenv("SUPPORT_API_KEY")\n\n' +
        "def verify(x_support_key: str = Header(None)):\n" +
        "    if x_support_key != SUPPORT_API_KEY:\n" +
        "        raise HTTPException(403)\n\n" +
        "@app.get('/lookup')\n" +
        "async def lookup(_ = Depends(verify)):\n    pass\n",
    },
    authenticationFailures
  );
  const v = vacuous(failures);
  assert.equal(v.length, 1, "the route is protected, so the vacuous finding stands alone");
  assert.match(v[0], /SUPPORT_API_KEY/);
  assert.match(v[0], /does not fail closed/);
});

test("a credential validated at startup is not vacuous", () => {
  for (const guard of [
    'if not SUPPORT_API_KEY:\n    raise RuntimeError("required")\n',
    "if SUPPORT_API_KEY is None:\n    raise RuntimeError()\n",
  ]) {
    const { failures } = run(
      {
        "src/main.py":
          "import os\n" +
          'SUPPORT_API_KEY = os.getenv("SUPPORT_API_KEY")\n' +
          guard +
          "\ndef verify(x_support_key: str = Header(None)):\n" +
          "    if x_support_key != SUPPORT_API_KEY:\n        raise HTTPException(403)\n\n" +
          "@app.get('/lookup')\nasync def lookup(_ = Depends(verify)):\n    pass\n",
      },
      authenticationFailures
    );
    assert.deepEqual(vacuous(failures), [], guard.split("\n")[0]);
  }
});

// os.environ[...] raises on a missing key, so it cannot be vacuous.
test("a credential read with os.environ[] is not vacuous", () => {
  const { failures } = run(
    {
      "src/main.py":
        "import os\n" +
        'SUPPORT_API_KEY = os.environ["SUPPORT_API_KEY"]\n\n' +
        "def verify(x_support_key: str = Header(None)):\n" +
        "    if x_support_key != SUPPORT_API_KEY:\n        raise HTTPException(403)\n\n" +
        "@app.get('/lookup')\nasync def lookup(_ = Depends(verify)):\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(vacuous(failures), []);
});

// TypeScript, from a real run. The Python adapter learned about request signatures after a webhook
// receiver was wrongly reported open; this adapter did not, so the next receiver -- same task, same
// defect class, different language -- was wrongly reported open too.
test("an Express route whose handler verifies a signature is authenticated", () => {
  const { failures } = run(
    {
      "src/index.ts":
        "import { handleWebhook } from './handlers/webhook';\n" +
        "app.post('/webhook', express.raw({ type: 'application/json' }), handleWebhook);\n",
      "src/handlers/webhook.ts":
        "import crypto from 'crypto';\n" +
        "export const handleWebhook = async (req, res) => {\n" +
        "  const digest = crypto.createHmac('sha256', secret).update(req.body).digest('hex');\n" +
        "  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(sig))) return res.status(401).send();\n" +
        "  return res.status(200).send();\n};\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// The corpus handed to an adapter is every file in that language concatenated. Reading a fixed
// window from a handler therefore runs past its end into the next file: an earlier attempt read
// 2500 characters from an unauthenticated handler, reached another route's signature code, and
// called the unauthenticated one verified. Worse than the miss it replaced.
test("signature verification in one handler does not protect another", () => {
  const { failures } = run(
    {
      "src/index.ts":
        "import { handleWebhook } from './handlers/webhook';\n" +
        "import { lookup } from './handlers/lookup';\n" +
        "app.post('/webhook', express.raw({ type: 'application/json' }), handleWebhook);\n" +
        "app.get('/lookup/:id', lookup);\n",
      "src/handlers/webhook.ts":
        "import crypto from 'crypto';\n" +
        "export const handleWebhook = async (req, res) => {\n" +
        "  const d = crypto.createHmac('sha256', s).update(req.body).digest('hex');\n" +
        "  return res.status(200).send();\n};\n",
      "src/handlers/lookup.ts":
        "export const lookup = async (req, res) => {\n  return res.status(200).json({});\n};\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /GET \/lookup/);
  assert.doesNotMatch(failures[0], /POST \/webhook/);
});

// process.env.X is undefined when unset and `undefined !== undefined` is false, exactly as in
// Python. The comparison is against the local the value was assigned to, not the env expression,
// which is why matching only on the env name found nothing in a deliverable that had the defect.
test("a TypeScript credential compared against an unset env var is vacuous", () => {
  const { failures } = run(
    {
      "src/index.ts": "app.get('/lookup/:id', requireSupportAuth, lookup);\n",
      "src/middleware.ts":
        "export const requireSupportAuth = (req, res, next) => {\n" +
        "  const supportKey = req.headers['x-support-key'];\n" +
        "  const expectedSupportKey = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (supportKey !== expectedSupportKey) return res.status(403).send();\n" +
        "  next();\n};\n",
    },
    authenticationFailures
  );
  assert.ok(failures.some((f) => /SUPPORT_TEAM_KEY/.test(f) && /does not fail closed/.test(f)));
});

test("a TypeScript credential guarded before comparison is not vacuous", () => {
  const { failures } = run(
    {
      "src/index.ts": "app.get('/lookup/:id', requireSupportAuth, lookup);\n",
      "src/middleware.ts":
        "export const requireSupportAuth = (req, res, next) => {\n" +
        "  const supportKey = req.headers['x-support-key'];\n" +
        "  const expectedKey = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (!expectedKey || !supportKey) return res.status(403).send();\n" +
        "  if (supportKey !== expectedKey) return res.status(403).send();\n" +
        "  next();\n};\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

// --- inline arrow handlers ---------------------------------------------------------------------
// Handler resolution originally worked by identifier, on the assumption that "Express handlers are
// named imports". An inline arrow has no identifier, so identical guarded logic was judged
// differently depending purely on handler shape. The three tests below are the probe that found it:
// the middle one is what proves the check is still live in that shape rather than dead.

const SIG_HELPERS =
  'import crypto from "crypto";\n' +
  'const SECRET = process.env.WEBHOOK_SECRET;\n' +
  "function verifySignature(raw, sig) {\n" +
  '  const mac = crypto.createHmac("sha256", SECRET).update(raw).digest();\n' +
  '  return crypto.timingSafeEqual(mac, Buffer.from(sig, "hex"));\n' +
  "}\n";

const GUARD =
  '  if (!verifySignature(req.rawBody, req.headers["x-signature"])) return res.status(401).end();\n';

test("named middleware with a signature guard is clean", () => {
  const { failures } = run(
    {
      "server.js":
        SIG_HELPERS +
        "function handleWebhook(req, res) {\n" + GUARD + "  res.json({ ok: true });\n}\n" +
        'app.post("/webhook", express.raw({ type: "*/*" }), handleWebhook);\n',
    },
    authenticationFailures
  );
  assert.deepEqual(failures, []);
});

test("named middleware with the guard removed still flags (the check is live in this shape)", () => {
  const { failures } = run(
    {
      "server.js":
        SIG_HELPERS +
        "function handleWebhook(req, res) {\n  res.json({ ok: true });\n}\n" +
        'app.post("/webhook", express.raw({ type: "*/*" }), handleWebhook);\n',
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /POST \/webhook/);
});

test("an inline arrow handler with the same guard is clean", () => {
  const { routes } = run(
    {
      "server.js":
        SIG_HELPERS +
        'app.post("/webhook", express.raw({ type: "*/*" }), (req, res) => {\n' +
        GUARD +
        "  res.json({ ok: true });\n});\n",
    },
    checkAuthentication
  );
  assert.equal(routes.length, 1);
  assert.equal(routes[0].protectedBy, "a verified request signature");
});

// Reading an inline body must not credit the NEXT route with it. A fixed-size window did exactly
// that once, reporting an unauthenticated endpoint as verified using another route's code — worse
// than the false positive it replaced, so both orderings are pinned here.
test("an inline body does not protect a following unguarded route", () => {
  const { routes, failures } = run(
    {
      "server.js":
        SIG_HELPERS +
        'app.post("/webhook", express.raw({ type: "*/*" }), (req, res) => {\n' +
        GUARD +
        "  res.json({ ok: true });\n});\n" +
        'app.get("/lookup/:id", (req, res) => {\n  res.json({ event: store.get(req.params.id) });\n});\n',
      "x.js": "",
    },
    (d) => ({ ...checkAuthentication(d), ...authenticationFailures(d) })
  );
  assert.equal(routes.find((r) => r.route === "/webhook").protectedBy, "a verified request signature");
  assert.equal(routes.find((r) => r.route === "/lookup/:id").protectedBy, null);
  assert.equal(failures.length, 1);
});

test("an unguarded inline route does not borrow a named handler defined after it", () => {
  const { routes } = run(
    {
      "server.js":
        SIG_HELPERS +
        'app.get("/lookup/:id", (req, res) => {\n  res.json({ event: store.get(req.params.id) });\n});\n' +
        "function handleWebhook(req, res) {\n" + GUARD + "  res.json({ ok: true });\n}\n" +
        'app.post("/webhook", express.raw({ type: "*/*" }), handleWebhook);\n',
    },
    checkAuthentication
  );
  assert.equal(routes.find((r) => r.route === "/lookup/:id").protectedBy, null);
  assert.equal(routes.find((r) => r.route === "/webhook").protectedBy, "a verified request signature");
});

// Express's chained form has the same shape gap, and worse: JS_CHAIN_VERB_RE's `[^)]*` argument
// capture stops at the first `)`, which an inline arrow's own parameter list supplies — so its
// `context` is the useless fragment "(req, res" and cannot see a guard at all.
test("a chained .route().post() with an inline guard is clean", () => {
  const { routes } = run(
    {
      "server.js":
        SIG_HELPERS +
        'app.route("/webhook").post((req, res) => {\n' + GUARD + "  res.json({ ok: true });\n});\n",
    },
    checkAuthentication
  );
  assert.equal(routes.length, 1);
  assert.equal(routes[0].protectedBy, "a verified request signature");
});

test("a chained .route().get() with no guard still flags", () => {
  const { routes } = run(
    {
      "server.js":
        SIG_HELPERS +
        'app.route("/lookup").get((req, res) => {\n  res.json({ event: store.get(req.query.id) });\n});\n',
    },
    checkAuthentication
  );
  assert.equal(routes[0].protectedBy, null);
});

// --- python credential headers ------------------------------------------------------------------
// The name list was fixed at six spellings, so a real support endpoint guarded by
// `x_internal_token` was reported as open to anyone. Found while grading webhook-5: the endpoint
// rejected every caller, and the gate called it unauthenticated.

test("a credential header the list never enumerated still counts", () => {
  const { routes } = run(
    {
      "app/main.py":
        "@app.get('/support/callbacks/{event_id}')\n" +
        "async def get_callback(event_id: str, x_internal_token: str = Header(None)):\n" +
        "    if x_internal_token != internal_token:\n" +
        "        raise HTTPException(status_code=403, detail='Unauthorized')\n" +
        "    return {}\n",
    },
    checkAuthentication
  );
  assert.equal(routes.length, 1);
  assert.equal(routes[0].protectedBy, "a credential header");
});

// The corroboration that makes widening the names safe. Declaring a credential parameter is not
// checking it, and a gate that invents protection is worse than one that misses it.
test("a credential header the handler never checks does NOT count", () => {
  const { routes } = run(
    {
      "app/main.py":
        "@app.get('/logs')\n" +
        "def read(x_internal_token: str = Header(None)):\n" +
        "    return db.all()\n",
    },
    checkAuthentication
  );
  assert.equal(routes[0].protectedBy, null);
});

test("a signature header is not credited as a plain credential", () => {
  const { routes } = run(
    {
      "app/main.py":
        "@app.post('/webhook')\n" +
        "async def hook(x_provider_signature: str = Header(None)):\n" +
        "    if not x_provider_signature:\n        raise HTTPException(status_code=401)\n" +
        "    return {}\n",
    },
    checkAuthentication
  );
  // Nothing in this project verifies a signature, so naming the header must not protect the route.
  assert.equal(routes[0].protectedBy, null);
});

// --- timing-unsafe comparison of a non-signature credential --------------------------------------
// A support token is a better timing target than a signature: it is stable across attempts, so one
// recovered value keeps working, and the caller may retry freely.

test("a bearer credential compared with != is reported", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.get('/support/{id}')\n" +
        "async def get(id: str, x_internal_token: str = Header(None)):\n" +
        "    if x_internal_token != internal_token:\n" +
        "        raise HTTPException(status_code=403)\n    return {}\n",
    },
    authenticationFailures
  );
  const timing = failures.filter((f) => /constant-time/.test(f));
  assert.equal(timing.length, 1);
  assert.match(timing[0], /x_internal_token/);
  assert.match(timing[0], /stable across attempts/);
});

// The bug this check shipped with for one revision: gating on "does the file compare anything in
// constant time" let a correct signature comparison suppress the report of an incorrect token one.
// webhook-5 had exactly that pair.
test("a correct signature comparison does not suppress an incorrect token comparison", () => {
  const { failures } = run(
    {
      "app/main.py":
        "def verify_signature(payload, signature):\n" +
        "    expected = hmac.new(k, payload, hashlib.sha256).hexdigest()\n" +
        "    return hmac.compare_digest(expected, signature)\n\n" +
        "@app.get('/support/{id}')\n" +
        "async def get(id: str, x_internal_token: str = Header(None)):\n" +
        "    if x_internal_token != internal_token:\n" +
        "        raise HTTPException(status_code=403)\n    return {}\n",
    },
    authenticationFailures
  );
  assert.equal(failures.filter((f) => /constant-time/.test(f)).length, 1);
});

test("a credential compared in constant time is clean", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.get('/support/{id}')\n" +
        "async def get(id: str, x_internal_token: str = Header(None)):\n" +
        "    if not hmac.compare_digest(x_internal_token, internal_token):\n" +
        "        raise HTTPException(status_code=403)\n    return {}\n",
    },
    authenticationFailures
  );
  assert.deepEqual(failures.filter((f) => /constant-time/.test(f)), []);
});

// One defect must not be reported under two names.
test("a loosely compared signature is the signature finding, not the credential one", () => {
  const { failures } = run(
    {
      "app/main.py":
        "@app.post('/webhook')\n" +
        "async def hook(x_signature: str = Header(None)):\n" +
        "    expected = hmac.new(k, body, hashlib.sha256).hexdigest()\n" +
        "    if expected != x_signature:\n" +
        "        raise HTTPException(status_code=401)\n    return {}\n",
    },
    authenticationFailures
  );
  const timing = failures.filter((f) => /constant-time/.test(f));
  assert.equal(timing.length, 1);
  assert.match(timing[0], /request signature/);
});

// Handler resolution was shared between the signature and credential checks only after the fact.
// The signature path learned to read inline arrow bodies; the credential path still resolved
// handlers by identifier, and an inline arrow has none — so identical guarded logic passed in a
// named middleware and flagged inline. Same defect as the one fixed a commit earlier, one path
// over, and in the same direction: a false positive, which is what gets a gate switched off.
test("a credential guard is judged the same inline as in a named middleware", () => {
  const body =
    "  const supportKey = req.headers['x-support-key'];\n" +
    "  const expectedKey = process.env.SUPPORT_TEAM_KEY;\n" +
    "  if (!expectedKey || !supportKey) return res.status(403).send();\n" +
    "  if (supportKey !== expectedKey) return res.status(403).send();\n";

  const named = run(
    {
      "src/index.ts": "app.get('/lookup', requireSupportAuth, lookup);\n",
      "src/middleware.ts": "export const requireSupportAuth = (req, res, next) => {\n" + body + "  next();\n};\n",
    },
    authenticationFailures
  );
  assert.deepEqual(named.failures, []);

  const inline = run(
    { "src/index.ts": "app.get('/lookup', (req, res) => {\n" + body + "});\n" },
    authenticationFailures
  );
  assert.deepEqual(inline.failures, [], "the same guard inline must reach the same verdict");
});

// The corroboration that keeps the wider resolution from inventing protection. Reading a header is
// not checking one — the `Depends(get_db)` mistake in another language.
test("a handler that reads a credential header but never refuses is still open", () => {
  const { failures } = run(
    {
      "src/index.ts":
        "app.get('/lookup', (req, res) => {\n" +
        "  const supportKey = req.headers['x-support-key'];\n" +
        "  res.json(store.all());\n});\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /GET \/lookup/);
});

// Per route, as everywhere else here: resolving more handler shapes must not let one guarded route
// vouch for the next one.
test("an inline credential guard does not protect a following route", () => {
  const { failures } = run(
    {
      "src/index.ts":
        "app.get('/lookup', (req, res) => {\n" +
        "  const expectedKey = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (!expectedKey) return res.status(403).send();\n" +
        "  if (req.headers['x-support-key'] !== expectedKey) return res.status(403).send();\n});\n" +
        "app.get('/open', (req, res) => { res.json(store.all()); });\n",
    },
    authenticationFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /GET \/open/);
  assert.doesNotMatch(failures[0], /GET \/lookup/);
});

// --- empty defaults and f-string comparisons -----------------------------------------------------
// From webhook-7, which passed the authentication gate clean while its support token defaulted to
// "" and was compared with an ordinary !=.

test('os.getenv(X, "") is vacuous — an empty default is not a default', () => {
  const { failures } = run(
    {
      "src/main.py":
        'SUPPORT_TEAM_TOKEN = os.getenv("SUPPORT_TEAM_TOKEN", "")\n\n' +
        "@app.get('/support/{id}')\n" +
        "async def get(id: str, authorization: str = Header(None)):\n" +
        '    if authorization != f"Bearer {SUPPORT_TEAM_TOKEN}":\n' +
        "        raise HTTPException(status_code=403)\n    return {}\n",
    },
    authenticationFailures
  );
  const v = vacuous(failures);
  assert.equal(v.length, 1);
  assert.match(v[0], /SUPPORT_TEAM_TOKEN/);
});

// The credential is inside an f-string, so it is not adjacent to the operator. Requiring adjacency
// meant the comparison was invisible and the finding never fired.
test("a credential interpolated into an f-string still counts as compared", () => {
  const { failures } = run(
    {
      "src/main.py":
        'API_TOKEN = os.getenv("API_TOKEN", "")\n' +
        "@app.get('/x')\n" +
        "def x(authorization: str = Header(None)):\n" +
        '    if authorization != f"Bearer {API_TOKEN}":\n        raise HTTPException(status_code=403)\n',
    },
    authenticationFailures
  );
  assert.equal(vacuous(failures).length, 1);
});

test("a real non-empty default is still treated as validated", () => {
  const { failures } = run(
    {
      "src/main.py":
        'SUPPORT_TEAM_TOKEN = os.getenv("SUPPORT_TEAM_TOKEN", "dev-only-placeholder")\n' +
        "@app.get('/support/{id}')\n" +
        "def get(id: str, x_api_key: str = Header(None)):\n" +
        "    if not compare_digest(x_api_key, SUPPORT_TEAM_TOKEN):\n        raise HTTPException(status_code=403)\n",
    },
    authenticationFailures
  );
  assert.deepEqual(vacuous(failures), []);
});

// PY_CREDENTIAL_HEADER_PARAM knew `authorization`; LEAKY_CREDENTIAL_COMPARE did not. Two lists in
// one file disagreeing about what a credential is called.
test("an authorization header compared with != is a timing finding", () => {
  const { failures } = run(
    {
      "src/main.py":
        'TOKEN = os.environ["TOKEN"]\n' +
        "@app.get('/x')\n" +
        "def x(authorization: str = Header(None)):\n" +
        '    if authorization != f"Bearer {TOKEN}":\n        raise HTTPException(status_code=403)\n',
    },
    authenticationFailures
  );
  const timing = failures.filter((f) => /constant-time/.test(f));
  assert.equal(timing.length, 1);
  assert.match(timing[0], /authorization/);
});

// --- a credential word beside `===` is not a credential comparison ---------
// `typeof apiKey !== "string"` is a type guard. Reporting it as a timing leak blocked a deliverable
// whose credential comparison used crypto.timingSafeEqual in another file, and four of that run's
// ten validation rounds went into a finding that was never real.
test("a typeof guard on a credential is not a leaky comparison", () => {
  assert.equal(
    leakyCredentialCheck(`
      const apiKey = req.headers['x-api-key'];
      if (!apiKey || typeof apiKey !== 'string') return res.status(401).end();
      const ok = crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    `),
    false
  );
});

test("presence checks against null, undefined and numbers are not leaky comparisons", () => {
  for (const src of [
    "if (token === undefined) return;",
    "if (apiKey === null) return;",
    "if (secret == None): return",
    "if (credential !== false) {}",
  ]) {
    assert.equal(leakyCredentialCheck(src), false, src);
  }
});

test("a genuine credential comparison is still reported", () => {
  assert.equal(leakyCredentialCheck("if x_internal_token != internal_token: abort(403)"), "x_internal_token");
});

// The scan must not stop at the first match. A benign comparison earlier in the file standing in
// for the rest is the same short-circuit as the file-wide constant-time bail-out that this check
// already had removed, one scope down.
test("a benign comparison earlier does not mask a real one later", () => {
  const src = `
    if (typeof apiKey !== 'string') return;
    if (token === undefined) return;
    if (supplied_token != stored_token) { deny(); }
  `;
  assert.equal(leakyCredentialCheck(src), "supplied_token");
});

// --- routing without a framework ------------------------------------------
// A deliverable served every endpoint from one node:http handler and this check found no routes at
// all: it said so honestly, blocked nothing, and contributed nothing to that run. Zero dependencies
// is a defensible choice and must not buy exemption from the auth gate.
const NODE_HTTP_APP = (guard) => `
  import { createServer } from "http";
  const CALLBACK_PATH = /^\\/callbacks\\/([^/]+)$/;

  ${guard}

  async function handleWebhook(req, res, svc) {
    const raw = await readRawBody(req);
    return svc.receive(raw, req.headers["x-webhook-signature"]);
  }
  async function handleGetCallback(req, res, id, svc) {
    return svc.getByEventId(id);
  }
  export function createApp({ svc }) {
    return createServer((req, res) => {
      const url = new URL(req.url, "http://localhost");
      if (req.method === "GET" && url.pathname === "/healthz") { return handleHealth(res); }
      if (req.method === "POST" && url.pathname === "/webhooks/payment-provider") {
        return handleWebhook(req, res, svc);
      }
      const match = CALLBACK_PATH.exec(url.pathname);
      if (req.method === "GET" && match) {
        return handleGetCallback(req, res, match[1], svc);
      }
    });
  }
`;

// The guard sits two calls below the dispatch branch, in another module -- handleWebhook calls
// receive(), and receive() is where the signature is verified.
const CHAINED_SERVICE = `
  import { createHmac, timingSafeEqual } from "crypto";
  export function verifySignature(secret, body, provided) {
    const expected = createHmac("sha256", secret).update(body).digest("hex");
    return provided.length === expected.length && timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
  }
  export function createService({ store }) {
    return {
      async receive(rawBody, header) {
        if (!verifySignature(store.secret, rawBody, header)) { throw new Error("bad signature"); }
        return store.put(rawBody);
      },
      async getByEventId(id) { return store.get(id); },
    };
  }
`;

test("a hand-rolled node:http dispatch is read as routes", () => {
  const { routes } = run({ "src/app.js": NODE_HTTP_APP(""), "src/svc.js": CHAINED_SERVICE }, (d) =>
    checkAuthentication(d)
  );
  const paths = routes.map((r) => `${r.method} ${r.route}`);
  assert.ok(paths.includes("POST /webhooks/payment-provider"), `got ${paths.join(", ")}`);
  // The path held in a regex constant, not a string literal.
  assert.ok(paths.includes("GET /callbacks/:param"), `got ${paths.join(", ")}`);
});

test("a guard two calls down, in another file, protects the route", () => {
  const { failures } = run({ "src/app.js": NODE_HTTP_APP(""), "src/svc.js": CHAINED_SERVICE }, (d) =>
    authenticationFailures(d)
  );
  // The webhook route is protected by a signature verified two calls away, in another module.
  assert.doesNotMatch(failures.join(" "), /webhooks\/payment-provider/);
  // The support route in this fixture genuinely has no guard, and must still be reported: the
  // point of following the chain is to see the guard that exists, not to assume one.
  assert.match(failures.join(" "), /GET \/callbacks\/:param/);
});

// The point of the chain walk is not to call everything protected. A project that verifies a
// signature SOMEWHERE, on a path this route never reaches, must still be reported.
test("a signature verified on an unreachable path does not protect the route", () => {
  const UNREACHED = `
    import { createHmac } from "crypto";
    export function verifySignature(secret, body, provided) {
      return createHmac("sha256", secret).update(body).digest("hex") === provided;
    }
    export function somethingElse() { return verifySignature("k", "b", "p"); }
  `;
  const NO_GUARD_SERVICE = `
    export function createService({ store }) {
      return {
        async receive(rawBody) { return store.put(rawBody); },
        async getByEventId(id) { return store.get(id); },
      };
    }
  `;
  const { failures } = run(
    { "src/app.js": NODE_HTTP_APP(""), "src/svc.js": NO_GUARD_SERVICE, "src/other.js": UNREACHED },
    (d) => authenticationFailures(d)
  );
  assert.ok(failures.length > 0, "an unguarded webhook route must still be reported");
  assert.match(failures.join(" "), /webhooks\/payment-provider/);
});

test("a health endpoint in a hand-rolled dispatch is open by convention", () => {
  const { failures } = run({ "src/app.js": NODE_HTTP_APP(""), "src/svc.js": CHAINED_SERVICE }, (d) =>
    authenticationFailures(d)
  );
  assert.doesNotMatch(failures.join(" "), /healthz/);
});

// --- Go handlers are methods on a receiver -------------------------------
// The first Go deliverable had BOTH endpoints reported as accepting requests from anyone, including
// one that reads Authorization and returns 401 on its seventh line. Two causes, both about handler
// shape rather than handler behaviour: `mux.HandleFunc("/lookup", s.handleLookup)` names its
// handler as a method VALUE, which the name extractor could not see past the dot; and
// `func (s *Server) handleLookup(...)` is a method, which the definition lookup did not match. The
// Go adapter then judged protection from an auth-ish word beside the route, which Go's standard
// library has no place to put -- the guard lives inside the handler.
const GO_SERVER = (webhookBody, lookupBody) => ({
  "main.go": `
    package main
    import ("net/http"; "crypto/hmac")

    func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
      ${webhookBody}
    }
    func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
      ${lookupBody}
    }
    func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
      w.WriteHeader(http.StatusOK)
    }
    func (s *Server) Start() error {
      mux := http.NewServeMux()
      mux.HandleFunc("/webhook", s.handleWebhook)
      mux.HandleFunc("/lookup", s.handleLookup)
      mux.HandleFunc("/health", s.handleHealth)
      return http.ListenAndServe(":8080", mux)
    }`,
});

const GUARDED_WEBHOOK = `
  signature := r.Header.Get("X-Signature")
  if !s.signer.Verify(body, signature, s.sharedKey) {
    http.Error(w, "Signature verification failed", http.StatusUnauthorized)
    return
  }`;
const GUARDED_LOOKUP = `
  apiKey := r.Header.Get("Authorization")
  if apiKey == "" {
    http.Error(w, "Missing API key", http.StatusUnauthorized)
    return
  }`;
const OPEN = `w.WriteHeader(http.StatusOK)`;

test("a Go method handler that verifies a signature is protected", () => {
  const { routes } = run(GO_SERVER(GUARDED_WEBHOOK, GUARDED_LOOKUP), (d) => checkAuthentication(d));
  const byPath = Object.fromEntries(routes.map((r) => [r.route, r.protectedBy]));
  assert.equal(byPath["/webhook"], "a verified request signature");
  assert.equal(byPath["/lookup"], "a credential checked in the handler");
});

test("a Go method handler with no guard is still reported", () => {
  const { failures } = run(GO_SERVER(OPEN, OPEN), (d) => authenticationFailures(d));
  assert.ok(failures.length > 0, "an unguarded Go handler must still be caught");
  assert.match(failures.join(" "), /\/webhook/);
  assert.match(failures.join(" "), /\/lookup/);
});

// Reading a header is not a control until something acts on it -- the same rule the Python and
// JavaScript adapters apply.
test("a Go handler that reads a credential and never refuses is not protected", () => {
  const { failures } = run(
    GO_SERVER(OPEN, `apiKey := r.Header.Get("Authorization")\n  _ = apiKey\n  w.WriteHeader(http.StatusOK)`),
    (d) => authenticationFailures(d)
  );
  assert.match(failures.join(" "), /\/lookup/);
});

test("a Go health endpoint stays exempt", () => {
  const { failures } = run(GO_SERVER(GUARDED_WEBHOOK, GUARDED_LOOKUP), (d) => authenticationFailures(d));
  assert.doesNotMatch(failures.join(" "), /health/);
});

// --- comments are not code -------------------------------------------------------------------
//
// This check read comments as code, and that failed in both directions. Running the gate on
// its own source blocked with two credential findings, both from comments in this checker quoting the
// patterns it was written against -- and a phantom POST /webhook from a comment that quotes a route,
// which is what let the credential findings be reported at all. The reverse was worse: a commented-
// out `app.use(requireAuth)` counted as protection, so a service with every route open passed.
//
// Full-line comments only. Cutting at a mid-line `//` would also cut code that follows a URL in a
// string, and a false negative in a security check costs more than a trailing comment's noise.

const credentialFindings = (failures) =>
  failures.filter((f) => /constant-time|does not fail closed/.test(f));

test("a comment quoting a vulnerable comparison is not a vulnerable comparison", () => {
  const { failures } = run(
    {
      "src/index.js":
        "// Or read inline at the comparison site: `req.headers['x'] !== process.env.SUPPORT_TEAM_KEY`.\n" +
        "// Observed in webhook-5: `x_internal_token != internal_token`.\n" +
        "/*\n" +
        " * authorization != process.env.SUPPORT_TEAM_KEY\n" +
        " */\n" +
        "app.get('/items', requireAuth, list);\n",
    },
    authenticationFailures
  );
  assert.deepEqual(credentialFindings(failures), []);
});

test("a Python comment quoting a vulnerable comparison is not one either", () => {
  const { failures } = run(
    {
      "app/main.py":
        "# Adjacency is too strict: `authorization != f\"Bearer {SUPPORT_TEAM_TOKEN}\"`\n" +
        "# SUPPORT_TEAM_TOKEN = os.getenv(\"SUPPORT_TEAM_TOKEN\")\n" +
        "@app.get('/items')\n" +
        "async def items(user = Depends(current_user)):\n    pass\n",
    },
    authenticationFailures
  );
  assert.deepEqual(credentialFindings(failures), []);
});

test("a commented-out route is not an endpoint", () => {
  // The phantom that let the gate's own credential findings through: with no real routes this
  // check reports "no HTTP routes were identified" and says nothing about credentials.
  const { routes, unknown } = run(
    {
      "src/notes.js":
        "// `app.post('/webhook', express.raw({...}), handleWebhook)`\n" +
        "export const x = 1;\n",
    },
    checkAuthentication
  );
  assert.deepEqual(routes, []);
  assert.match(unknown, /no HTTP routes/);
});

test("commented-out middleware is not protection", () => {
  // The false negative: every route open, and a comment saying auth used to be here was enough.
  for (const off of ["// app.use(requireAuth);\n", "/* app.use(requireAuth); */\n", "/*\n  app.use(requireAuth);\n*/\n"]) {
    const { failures } = run(
      {
        "src/app.js":
          "const app = express();\n" + off +
          "app.get('/records', (req, res) => res.json([]));\n" +
          "app.post('/records', (req, res) => res.status(201).end());\n",
      },
      authenticationFailures
    );
    assert.ok(
      failures.some((f) => /2 of 2 endpoint/.test(f)),
      `routes stay open when the middleware is commented out as: ${JSON.stringify(off)}`
    );
  }
});

test("a real comparison after a URL in a string is still caught", () => {
  // The reason stripping is full-line only. Cutting at `//` would remove the comparison below.
  const { failures } = run(
    {
      "src/app.js":
        "app.get('/lookup', requireSupport, lookup);\n" +
        "function requireSupport(req, res, next) {\n" +
        "  const docs = \"https://example.com/support\"; if (req.headers.authorization !== process.env.SUPPORT_TEAM_KEY) return res.status(403).end();\n" +
        "  next();\n}\n",
    },
    authenticationFailures
  );
  assert.ok(credentialFindings(failures).length > 0, "the comparison on that line is code");
});

test("stripping a block comment does not move the lines after it", () => {
  const { routes } = run(
    {
      "src/app.js":
        "/*\n * one\n * two\n */\n" +
        "app.get('/open', (req, res) => res.end());\n",
    },
    checkAuthentication
  );
  assert.equal(routes[0].line, 5, "reported at its real line");
});

// --- where a finding is ----------------------------------------------------------------------
//
// These two checks run over every file of a language joined into one string, so the file that
// matched was lost and the finding said only what was wrong, never where. An agent handed that
// on a repository it did not write concluded, correctly as it happened, that it was "sample code"
// -- by guessing.

test("a vacuous credential finding names the file and line", () => {
  const { failures } = run(
    {
      "src/index.ts": "app.get('/lookup/:id', requireSupportAuth, lookup);\n",
      "src/middleware.ts":
        "export const requireSupportAuth = (req, res, next) => {\n" +
        "  const supportKey = req.headers['x-support-key'];\n" +
        "  const expectedSupportKey = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (supportKey !== expectedSupportKey) return res.status(403).send();\n" +
        "  next();\n};\n",
    },
    authenticationFailures
  );
  const v = vacuous(failures);
  assert.equal(v.length, 1);
  assert.match(v[0], /src\/middleware\.ts:4/);
});

test("a leaky credential finding names the file and line", () => {
  const { failures } = run(
    {
      "app/main.py":
        "import os, hmac\n" +
        'INTERNAL = os.environ["INTERNAL_TOKEN"]\n' +
        "def verify(x_internal_token: str = Header(...)):\n" +
        "    if x_internal_token != INTERNAL:\n" +
        "        raise HTTPException(403)\n" +
        "@app.get('/support')\n" +
        "async def support(_ = Depends(verify)):\n    pass\n",
    },
    authenticationFailures
  );
  const leaky = failures.filter((f) => /constant-time/.test(f) && !/does not fail closed/.test(f));
  assert.equal(leaky.length, 1);
  assert.match(leaky[0], /app\/main\.py:4/);
});

// --- words for the language that matched ------------------------------------------------------

test("the vacuous finding is worded for JavaScript when JavaScript matched", () => {
  const { failures } = run(
    {
      "src/index.ts": "app.get('/lookup/:id', requireSupportAuth, lookup);\n",
      "src/middleware.ts":
        "export const requireSupportAuth = (req, res, next) => {\n" +
        "  const expectedKey = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (req.headers['x-support-key'] !== expectedKey) return res.status(403).send();\n" +
        "  next();\n};\n",
    },
    authenticationFailures
  );
  const [v] = vacuous(failures);
  assert.match(v, /undefined/);
  assert.match(v, /timingSafeEqual/);
  assert.doesNotMatch(v, /\bNone\b/, "not Python's word for it");
});

test("the vacuous finding is worded for Python when Python matched", () => {
  const { failures } = run(
    {
      "src/main.py":
        "import os\n" +
        'SUPPORT_API_KEY = os.getenv("SUPPORT_API_KEY")\n\n' +
        "def verify(x_support_key: str = Header(None)):\n" +
        "    if x_support_key != SUPPORT_API_KEY:\n" +
        "        raise HTTPException(403)\n\n" +
        "@app.get('/lookup')\n" +
        "async def lookup(_ = Depends(verify)):\n    pass\n",
    },
    authenticationFailures
  );
  const [v] = vacuous(failures);
  assert.match(v, /\bNone\b/);
  assert.match(v, /compare_digest/);
  assert.doesNotMatch(v, /\bundefined\b/);
});

// --- a credential held in a local whose name does not look like one ---------------------------
//
// The detector required Key/Secret/Token/Password/Credential in the LOCAL name, on top of the same
// test applied to the env name, so `const expected = process.env.SUPPORT_TEAM_KEY` was never examined
// and a vacuous comparison against `expected` passed. Any local is examined now. An arbitrary name
// must be an operand of the comparison, though, not merely share a line with one: `v` or `value`
// sits on unrelated comparison lines everywhere, and a false positive in a blocking check is how a
// gate gets switched off. Measured over 36 real codebases on the author's machine, neither the strict
// nor the loose version changed a single verdict; the strict one is kept for the case below, which
// is easy to write and which the loose one gets wrong.

const vacuousJs = (body) => ({
  "src/index.ts": "app.get('/lookup/:id', requireSupport, lookup);\n",
  "src/middleware.ts": "export const requireSupport = (req, res, next) => {\n" + body + "  next();\n};\n",
});

test("a credential in a local with an ordinary name is still examined", () => {
  const { failures } = run(
    vacuousJs(
      "  const expected = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (req.headers['x-support-key'] !== expected) return res.status(403).send();\n"
    ),
    authenticationFailures
  );
  assert.ok(
    vacuous(failures).some((f) => /SUPPORT_TEAM_KEY/.test(f)),
    "the env name says what the value is; the local is whatever someone called it"
  );
});

test("an ordinarily named local that only shares a line with a comparison is not a comparison", () => {
  // The case that separates the strict rule from the loose one. `v` is logged on a line that
  // happens to compare two other things; it is never compared with anything.
  const { failures } = run(
    vacuousJs(
      "  const v = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (req.method === 'GET') console.log('key length', v.length);\n"
    ),
    authenticationFailures
  );
  assert.deepEqual(vacuous(failures), []);
});

test("an ordinarily named local validated at startup is not vacuous", () => {
  const { failures } = run(
    vacuousJs(
      "  const expected = process.env.SUPPORT_TEAM_KEY;\n" +
        "  if (!expected) throw new Error('SUPPORT_TEAM_KEY is required');\n" +
        "  if (req.headers['x-support-key'] !== expected) return res.status(403).send();\n"
    ),
    authenticationFailures
  );
  assert.deepEqual(vacuous(failures), []);
});

test("an ordinarily named local holding something that is not a credential is ignored", () => {
  const { failures } = run(
    vacuousJs("  const expected = process.env.REGION;\n  if (req.headers['x-region'] !== expected) return res.status(400).send();\n"),
    authenticationFailures
  );
  assert.deepEqual(vacuous(failures), []);
});

// --- the fix named in the framework the route is written in ------------------------------------
// A Flask app was told to add "a FastAPI dependency". Each case is a route reported open, the
// advice it must get (and must not: another framework's), and the same route changed the way the
// advice says, which must then pass. Advice this check does not credit sends the reader in a circle.
const OPEN_ROUTE = /accept requests from anyone/;
const ADVICE_CASES = [
  {
    framework: "FastAPI",
    open: { "app.py": 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/reports")\ndef reports():\n    return []\n' },
    fixed: {
      "app.py":
        'from fastapi import Depends, FastAPI\n\napp = FastAPI()\n\n\ndef get_current_user():\n    pass\n\n\n' +
        '@app.get("/reports")\ndef reports(user=Depends(get_current_user)):\n    return []\n',
    },
    says: /Depends\(get_current_user\)/,
    not: /abort\(401\)|Flask/,
  },
  {
    framework: "Flask",
    open: { "app.py": 'from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.get("/reports")\ndef reports():\n    return []\n' },
    fixed: {
      "app.py":
        'from flask import Flask\nfrom flask_login import login_required\n\napp = Flask(__name__)\n\n\n' +
        '@app.get("/reports")\n@login_required\ndef reports():\n    return []\n',
    },
    says: /`@login_required` \(Flask-Login\) under the route decorator, a `before_request` hook/,
    not: /FastAPI|Depends/,
  },
  {
    framework: "Express",
    open: { "server.js": "const express = require('express');\nconst app = express();\napp.get('/reports', (req, res) => res.json([]));\n" },
    fixed: {
      "server.js":
        "const express = require('express');\nconst app = express();\nfunction requireAuth(req, res, next) {\n" +
        "  if (!req.session.user) return res.status(401).end();\n  next();\n}\napp.get('/reports', requireAuth, (req, res) => res.json([]));\n",
    },
    says: /app\.use\(requireAuth\)/,
    not: /Fastify|preHandler|UseGuards/,
  },
  {
    framework: "Fastify",
    open: { "server.js": "const fastify = require('fastify')();\nfastify.get('/reports', async () => []);\n" },
    fixed: {
      "server.js":
        "const fastify = require('fastify')();\nasync function authenticate(request, reply) {\n" +
        "  if (!request.user) return reply.code(401).send();\n}\nfastify.get('/reports', { preHandler: authenticate }, async () => []);\n",
    },
    says: /`preHandler` or `onRequest` hook on the route/,
    not: /app\.use|UseGuards/,
  },
  {
    framework: "NestJS",
    open: {
      "src/reports.controller.ts":
        "import { Controller, Get } from '@nestjs/common';\n\n@Controller('reports')\nexport class ReportsController {\n" +
        "  @Get()\n  list() {\n    return [];\n  }\n}\n",
    },
    // The guard below the route decorator, as TypeScript allows: it read as open while only the
    // lines above were read.
    fixed: {
      "src/reports.controller.ts":
        "import { Controller, Get, UseGuards } from '@nestjs/common';\nimport { AuthGuard } from '@nestjs/passport';\n\n" +
        "@Controller('reports')\nexport class ReportsController {\n  @Get()\n  @UseGuards(AuthGuard('jwt'))\n  list() {\n    return [];\n  }\n}\n",
    },
    says: /@UseGuards\(\.\.\.\)` on the controller class or on the route's method/,
    not: /app\.use|preHandler/,
  },
  {
    framework: "Sinatra",
    open: { "app.rb": "require 'sinatra'\n\nget '/reports' do\n  '[]'\nend\n" },
    fixed: { "app.rb": "require 'sinatra'\n\nbefore do\n  halt 401 unless session[:user_id]\nend\n\nget '/reports' do\n  '[]'\nend\n" },
    says: /`before` filter.*halt 401/,
    not: /before_action/,
  },
  {
    framework: "ASP.NET Core controller",
    open: {
      "Controllers/ReportsController.cs":
        '[ApiController]\n[Route("api/[controller]")]\npublic class ReportsController : ControllerBase\n{\n' +
        "    [HttpGet]\n    public IActionResult Get() { return Ok(); }\n}\n",
    },
    fixed: {
      "Controllers/ReportsController.cs":
        '[Authorize]\n[ApiController]\n[Route("api/[controller]")]\npublic class ReportsController : ControllerBase\n{\n' +
        "    [HttpGet]\n    public IActionResult Get() { return Ok(); }\n}\n",
    },
    says: /`\[Authorize\]` on the controller or action/,
    not: /on the endpoint or its group/,
  },
  {
    framework: "ASP.NET Core minimal API",
    open: { "Program.cs": 'var app = builder.Build();\napp.MapGet("/reports", () => Results.Ok());\napp.Run();\n' },
    fixed: { "Program.cs": 'var app = builder.Build();\napp.MapGet("/reports", () => Results.Ok()).RequireAuthorization();\napp.Run();\n' },
    says: /`\.RequireAuthorization\(\)` on the endpoint or its group/,
    not: /\[Authorize\]/,
  },
  {
    framework: "Laravel",
    open: { "routes/web.php": "<?php\n\nRoute::get('/reports', [ReportController::class, 'index']);\n" },
    fixed: { "routes/web.php": "<?php\n\nRoute::get('/reports', [ReportController::class, 'index'])->middleware('auth');\n" },
    says: /the `auth` middleware on the route or its group/,
    not: /IsGranted|access_control/,
  },
  {
    framework: "Symfony",
    open: {
      "src/Controller/ReportController.php":
        "<?php\nclass ReportController extends AbstractController\n{\n    #[Route('/reports', methods: ['GET'])]\n    public function index(): Response {}\n}\n",
    },
    fixed: {
      "src/Controller/ReportController.php":
        "<?php\nclass ReportController extends AbstractController\n{\n    #[Route('/reports', methods: ['GET'])]\n" +
        "    #[IsGranted('ROLE_USER')]\n    public function index(): Response {}\n}\n",
    },
    says: /`#\[IsGranted\]` on the controller or action/,
    not: /middleware/,
  },
  {
    framework: "Spring",
    open: { "src/main/kotlin/ReportController.kt": '@RestController\nclass ReportController {\n    @GetMapping("/reports")\n    fun list(): String = "[]"\n}\n' },
    fixed: {
      "src/main/kotlin/ReportController.kt":
        '@RestController\nclass ReportController {\n    @GetMapping("/reports")\n    @PreAuthorize("isAuthenticated()")\n    fun list(): String = "[]"\n}\n',
    },
    says: /`@PreAuthorize` on the handler or its class/,
    not: /authenticate \{/,
  },
  {
    framework: "Ktor",
    open: { "src/main/kotlin/Routes.kt": 'fun Application.module() {\n    routing {\n        get("/reports") { call.respondText("[]") }\n    }\n}\n' },
    fixed: {
      "src/main/kotlin/Routes.kt":
        'fun Application.module() {\n    routing {\n        authenticate {\n            get("/reports") { call.respondText("[]") }\n        }\n    }\n}\n',
    },
    says: /`authenticate \{ \}` around the routes/,
    not: /PreAuthorize/,
  },
];

for (const c of ADVICE_CASES) {
  test(`advice for a ${c.framework} route names the ${c.framework} fix, and the fix passes`, () => {
    const report = run(c.open, checkAuthentication);
    assert.deepEqual(
      report.routes.map((r) => r.framework),
      [c.framework],
      "the route is read as " + c.framework
    );
    const { failures } = run(c.open, authenticationFailures);
    const open = failures.filter((f) => OPEN_ROUTE.test(f));
    assert.equal(open.length, 1, failures.join("\n"));
    assert.match(open[0], c.says);
    assert.doesNotMatch(open[0], c.not);
    const after = run(c.fixed, authenticationFailures).failures;
    assert.deepEqual(after.filter((f) => OPEN_ROUTE.test(f)), [], "following the advice passes");
  });
}

test("a route file that imports only the app object takes the project's framework", () => {
  const { failures } = run(
    {
      "app/__init__.py": "from flask import Flask\n\napp = Flask(__name__)\n",
      "app/routes.py": 'from app import app\n\n\n@app.get("/reports")\ndef reports():\n    return []\n',
    },
    authenticationFailures
  );
  assert.match(failures[0], /abort\(401\)/);
  assert.doesNotMatch(failures[0], /FastAPI/);
});

test("the advice names the fix for each framework that has an open route, and only those", () => {
  const { failures } = run(
    {
      "api/app.py": 'from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.get("/reports")\ndef reports():\n    return []\n',
      "web/server.js":
        "const express = require('express');\nconst app = express();\nfunction requireAuth(req, res, next) {\n" +
        "  if (!req.session.user) return res.status(401).end();\n  next();\n}\napp.get('/x', requireAuth, (req, res) => res.json([]));\n" +
        "app.get('/y', (req, res) => res.json([]));\n",
      "Program.cs": 'var app = builder.Build();\napp.MapGet("/z", () => Results.Ok()).RequireAuthorization();\napp.Run();\n',
    },
    authenticationFailures
  );
  const open = failures.find((f) => OPEN_ROUTE.test(f));
  assert.match(open, /abort\(401\)/);
  assert.match(open, /app\.use\(requireAuth\)/);
  assert.doesNotMatch(open, /RequireAuthorization|\[Authorize\]/, "the C# route is protected, so its fix is not advice");
});

// --- Rails routing ------------------------------------------------------------------------------
// Mastodon's shape: routes.rb lines with a block matched the Sinatra form, and a before_action in an
// unrelated controller marked them all protected -- its public profile page among them.
const RAILS_APP = {
  "config/routes.rb":
    "Rails.application.routes.draw do\n  get '/users/:username', to: redirect { |params, req| \"/@#{params[:username]}\" }\n" +
    "  get '/health' do\n    [200, {}, ['ok']]\n  end\n  resources :reports\nend\n",
  "app/controllers/admin_controller.rb": "class AdminController < ApplicationController\n  before_action :authenticate_user!\nend\n",
};

test("rails: routes.rb is not read as routes, and is reported as not checked", () => {
  const report = run(RAILS_APP, checkAuthentication);
  assert.deepEqual(report.routes, []);
  assert.deepEqual(report.unread, ["config/routes.rb"]);
  const { failures, advisories } = run(RAILS_APP, authenticationFailures);
  assert.deepEqual(failures, []);
  assert.equal(advisories.length, 1, "the Rails sentence replaces the general no-routes one");
  assert.match(advisories[0], /^authentication: Rails routing is not read, so the routes declared in config\/routes\.rb were not checked/);
});

test("rails: the advisory stands beside the findings for routes that are read", () => {
  const { failures, advisories } = run(
    { ...RAILS_APP, "web/server.js": "const express = require('express');\nconst app = express();\napp.get('/x', (req, res) => res.json([]));\n" },
    authenticationFailures
  );
  assert.match(failures[0], /1 of 1 endpoint\(s\)/);
  assert.ok(advisories.some((a) => /^authentication: Rails routing is not read/.test(a)), advisories.join("\n"));
});

test("rails: route files drawn from config/routes/ are Rails routing too", () => {
  const report = run(
    {
      "config/routes/admin.rb": "namespace :admin do\n  get '/stats' do\n    [200, {}, ['x']]\n  end\nend\n",
      "config/routes.rb": "Rails.application.routes.draw do\n  draw(:admin)\nend\n",
    },
    checkAuthentication
  );
  assert.deepEqual(report.routes, []);
  assert.deepEqual(report.unread, ["config/routes.rb", "config/routes/admin.rb"], "routes.rb first");
});
