// Authentication written inside a handler (agent/auth-handler.mjs, docs/candidate-rules.md #25).
// The cases come from the calibration applications where they were found, and each "no" is a shape
// that reads like a guard and is not one.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { handlerGuard } from "./auth-handler.mjs";
import { checkAuthentication, authenticationFailures } from "./authentication.mjs";

const YES = [
  ["Bitwarden's Apple webhook: a key compared in constant time, 400 on a mismatch", "brace", `public async Task<IActionResult> PostIap()
    {
        if (HttpContext?.Request?.Query == null)
        {
            return new BadRequestResult();
        }
        var key = HttpContext.Request.Query.TryGetValue("key", out var keyValue) ? keyValue.ToString() : null;
        if (!CoreHelpers.FixedTimeEquals(key, _billingSettings.AppleWebhookKey))
        {
            return new BadRequestResult();
        }
        return Ok(await Process());
    }`, "a secret checked in the handler"],
  ["Bitwarden's sponsorship status: the caller's role, and 'not found' to anyone else", "brace", `public async Task<object> GetSyncStatus(Guid sponsoringOrgId)
    {
        var sponsoringOrg = await _organizationRepository.GetByIdAsync(sponsoringOrgId);
        if (!await _currentContext.OrganizationOwner(sponsoringOrg.Id))
        {
            throw new NotFoundException();
        }
        return new M(await x.Get(sponsoringOrg.Id));
    }`, "the caller checked in the handler"],
  ["kweet's delete: no session, or not the author, and the work is in the else", "brace", `post<KweetDelete> {
        val user = call.sessions.get<KweetSession>()?.let { dao.user(it.userId) }
        val date = post["date"]?.toLongOrNull() ?: return@post call.redirect(ViewKweet(it.id))
        val kweet = dao.getKweet(it.id)
        if (user == null || kweet.userId != user.userId || !call.verifyCode(date, user, code, hashFunction)) {
            call.redirect(ViewKweet(it.id))
        } else {
            dao.deleteKweet(it.id)
            call.redirect(Index())
        }
    }`, "the caller checked in the handler"],
  ["youkube's upload: 403 without a session", "brace", `post<Upload> {
        val session = call.sessions.get<YouKubeSession>()
        if (session == null) {
            call.respond(HttpStatusCode.Forbidden.description("Not logged in"))
        } else {
            val multipart = call.receiveMultipart()
        }
    }`, "the caller checked in the handler"],
  ["Gitea's artifact preview: one failing arm of an OR is enough", "brace", `func ArtifactsPreviewRawView(resp http.ResponseWriter, req *http.Request) {
	artifactID, expires := ctx.PathParamInt64("artifact_id"), ctx.PathParamInt64("expires")
	if !setting.Actions.Enabled || expires < int64(timeutil.TimeStampNow()) ||
		!hmac.Equal([]byte(ctx.PathParam("signature")), []byte(artifactPreviewSignature(artifactID, expires))) {
		ctx.HTTPError(http.StatusNotFound)
		return
	}
	serve(ctx)
}`, "a request signature verified in the handler"],
  ["Gitea's LFS locks: an authenticate() call, and 401", "brace", `func GetListLockHandler(ctx *context.Context) {
	authenticated := authenticate(ctx, repository, rv.Authorization, true, false)
	if !authenticated {
		ctx.JSON(http.StatusUnauthorized, api.LFSLockError{Message: "no"})
		return
	}
	ctx.JSON(http.StatusOK, x)
}`, "the caller checked in the handler"],
  ["Gitea's issue edits: not signed in, 403", "brace", `func UpdateIssueTitle(ctx *context.Context) {
	issue := GetActionIssue(ctx)
	if !ctx.IsSigned || (!issue.IsPoster(ctx.Doer.ID) && !ctx.Repo.Permission.CanWriteIssuesOrPulls(issue.IsPull)) {
		ctx.HTTPError(http.StatusForbidden)
		return
	}
	save(ctx)
}`, "the caller checked in the handler"],
  ["WebGoat's diagnostics: a header token against an internal one, 401", "brace", `public ResponseEntity<Map<String, String>> diagnostics(@RequestHeader(value = INTERNAL_HEADER, required = false) String token) {
    if (!state.internalToken().equals(token)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    return ResponseEntity.ok(Map.of("status", "UP"));
  }`, "a credential checked in the handler"],
  ["Flask: an admin token compared in constant time, 403", "python", `def report():
    if not hmac.compare_digest(request.headers.get("X-Admin-Token", ""), os.environ["ADMIN_TOKEN"]):
        abort(403)
    return {"rows": 1}`, "a secret checked in the handler"],
  ["Flask: an HMAC computed, then compared through a name", "python", `def payment_hook():
    expected = hmac.new(os.environ["PAYMENTS_SECRET"].encode(), request.data, hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, request.headers.get("X-Signature", ""))
    if not valid:
        abort(401)
    return {"ok": True}`, "a request signature verified in the handler"],
  ["Flask: an API key against the environment, 401", "python", `def item():
    token = request.headers.get("X-Api-Key")
    if token != os.environ["API_KEY"]:
        return jsonify(error="no"), 401
    return "ok"`, "a credential checked in the handler"],
  ["Laravel: abort_unless with a constant-time compare", "brace", `function (Request $request) {
        abort_unless(hash_equals(config('services.hook.secret'), (string) $request->header('X-Hook-Token')), 403);
        return response()->json(['ok' => true]);
    }`, "a secret checked in the handler"],
  ["Laravel: abort_unless with every condition required", "brace", `function (Request $request) {
        abort_unless(auth()->check() && $request->user()->isAdmin(), 403);
        return 1;
    }`, "the caller checked in the handler"],
  ["Sinatra: halt 401 unless a token matches the environment", "ruby", `get '/admin' do
  halt 401 unless params[:token] == ENV['ADMIN_TOKEN']
  'ok'
end`, "a credential checked in the handler"],
  ["Express: no session, 401", "brace", `async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "sign in" });
  res.json(await db.all());
}`, "the caller checked in the handler"],
  ["the work in the if, the refusal in the else", "brace", `public IActionResult X(string key) {
    if (CoreHelpers.FixedTimeEquals(key, _settings.Key)) { return Ok(Do()); } else { return Unauthorized(); }
}`, "a secret checked in the handler"],
  ["Gitea's LFS lock list: reads, a header set beside a 401, a check-named call, then the guard", "brace", `func GetListLockHandler(ctx *context.Context) {
	rv := getRequestContext(ctx)
	repository, err := repo_model.GetRepositoryByOwnerAndName(ctx, rv.User, rv.Repo)
	if err != nil {
		log.Debug("Could not find repository: %s/%s - %s", rv.User, rv.Repo, err)
		ctx.Resp.Header().Set("WWW-Authenticate", \`Basic realm="gitea-lfs"\`)
		ctx.JSON(http.StatusUnauthorized, api.LFSLockError{Message: "no"})
		return
	}
	repository.MustOwner(ctx)
	context.CheckRepoScopedToken(ctx, repository, auth_model.Read)
	if ctx.Written() {
		return
	}
	authenticated := authenticate(ctx, repository, rv.Authorization, true, false)
	if !authenticated {
		ctx.JSON(http.StatusUnauthorized, api.LFSLockError{Message: "no"})
		return
	}
	ctx.JSON(http.StatusOK, list(ctx))
}`, "the caller checked in the handler"],
  ["Gitea's comment reactions: an error answered and a load in an if header come first", "brace", `func ChangeCommentReaction(ctx *context.Context) {
	comment, err := issues_model.GetCommentByID(ctx, ctx.PathParamInt64("id"))
	if err != nil {
		ctx.ServerError("GetCommentByID", err)
		return
	}
	if err := comment.LoadIssue(ctx); err != nil {
		ctx.ServerError("LoadIssue", err)
		return
	}
	if !ctx.IsSigned || ctx.Doer.ID != comment.PosterID {
		ctx.HTTPError(http.StatusForbidden)
		return
	}
	react(ctx, comment)
}`, "the caller checked in the handler"],
  ["Flask-Login: an anonymous caller sent to sign in", "python", `def settings():
    """The account page."""
    if current_user.is_anonymous:
        return redirect(url_for("auth.login"))
    return render_template("settings.html")`, "the caller checked in the handler"],
  ["Rails: no user in the session, sent to sign in", "ruby", `def edit
  return redirect_to(login_path) if session[:user_id].nil?
  render :edit
end`, "the caller checked in the handler"],
  ["Ktor: no session, sent to sign in", "brace", `get<Upload> {
        val session = call.sessions.get<YouKubeSession>() ?: return@get call.respondRedirect(Login())
        call.respond(upload(session))
    }`, "the caller checked in the handler"],
  ["microblog's password reset: a signed-in user turned away, then the reset token verified", "python", `def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html')`, "a secret checked in the handler"],
  ["Bitwarden's policies by invite token: a C# property pattern in the first if's condition", "brace", `public async Task<ListResponseModel<PolicyResponseModel>> GetByToken(Guid orgId, [FromQuery] string token)
    {
        var organizationAbility = await _organizationAbilityCacheService.GetOrganizationAbilityAsync(orgId);

        if (organizationAbility is not { UsePolicies: true })
        {
            throw new NotFoundException();
        }

        var tokenValid = OrgUserInviteTokenable.ValidateOrgUserInviteStringToken(
            _orgUserInviteTokenDataFactory, token, organizationUserId, email);

        if (!tokenValid)
        {
            throw new NotFoundException();
        }
        return new ListResponseModel<PolicyResponseModel>(await Load(orgId));
    }`, "a secret checked in the handler"],
  ["dvcsharp-api's password reset: 400s that add model errors come before the key lookup", "brace", `public IActionResult Put([FromBody] PasswordResetRequest passwordResetRequest)
      {
         if(String.IsNullOrEmpty(passwordResetRequest.key)) {
            ModelState.AddModelError("key", "Key is required for password reset");
            return BadRequest(ModelState);
         }
         var resetRequest = _context.PasswordResetRequests.
            Where(b => b.key == passwordResetRequest.key).FirstOrDefault();
         if(resetRequest == null) {
            ModelState.AddModelError("key", "Key not found in system");
            return BadRequest(ModelState);
         }
         _context.SaveChanges();
         return Ok();
      }`, "a credential checked in the handler"],
];

const NO = [
  ["Bitwarden's job runner: it branches on a job name, not on the caller", "brace", `public async Task<IActionResult> RunJobAsync(string jobName)
    {
        if (jobName == nameof(SendInvoicePriceMigrationJob))
        {
            await jobsHostedService.TriggerJobNowAsync<SendInvoicePriceMigrationJob>();
            return Ok(new { message = "ok" });
        }
        return BadRequest(new { error = "Unknown job name" });
    }`],
  ["Jellyfin's splashscreen: refused only when the feature is off AND the caller is not an admin", "brace", `public async Task<ActionResult> GetSplashscreen([FromQuery] string? tag)
    {
        var brandingOptions = _serverConfigurationManager.GetConfiguration<BrandingOptions>("branding");
        var isAdmin = User.IsInRole(Constants.UserRoles.Administrator);
        if (!brandingOptions.SplashscreenEnabled && !isAdmin)
        {
            return NotFound();
        }
        return File(x);
    }`],
  ["dvcsharp-api: a password against its confirmation", "brace", `public IActionResult Put([FromBody] PasswordResetRequest passwordResetRequest)
      {
         if(passwordResetRequest.password != passwordResetRequest.passwordConfirmation) {
            return BadRequest(ModelState);
         }
         return Ok();
      }`],
  ["a password against its confirmation in another variable", "brace", `public IActionResult Register(string password, string confirmPassword) {
    if (password != confirmPassword) { return BadRequest(); }
    return Ok(Create());
}`],
  ["a token type against a literal naming one is validation", "python", `def exchange():
    if request.form["token_type"] != "access_token":
        abort(400)
    return issue()`],
  ["kweet's index: a session read, nothing refused", "brace", `get<Index> {
        val user = call.sessions.get<KweetSession>()?.let { dao.user(it.userId) }
        call.respond(FreeMarkerContent("index.ftl", mapOf("user" to user), etag.toString()))
    }`],
  ["a database session is not a user's session", "python", `def item(id):
    row = session.query(Item).get(id)
    if row is None:
        abort(404)
    return row.to_dict()`],
  ["a check nested under another branch protects one path", "python", `def item(id):
    if request.method == "POST":
        if request.headers.get("X-Token") != os.environ["T"]:
            abort(403)
    return "ok"`],
  ["a credential-named value against a literal is validation", "brace", `function (Request $request) {
        if ($request->input('sortKey') !== 'date') { abort(400); }
        return 1;
    }`],
  ["a check whose branch only logs does not end the request", "brace", `public IActionResult X(string key) {
    if (!CoreHelpers.FixedTimeEquals(key, _settings.Key)) { _logger.LogWarning("bad key"); }
    return Ok(Do());
}`],
  ["a 401 set without returning lets the handler carry on", "brace", `async (req, res) => {
  if (!req.session.user) { res.status(401); }
  res.json(await db.all());
}`],
  ["an if/else that refuses without ending, with more work after it", "brace", `get("/x") {
        val session = call.sessions.get<UserSession>()
        if (session == null) {
            call.redirect(Login())
        } else {
            log(session)
        }
        call.respond(db.all())
    }`],
  ["a negated OR is an AND: refused only when both fail", "brace", `public IActionResult X(string key) {
    if (!(CoreHelpers.FixedTimeEquals(key, _settings.Key) || _settings.Open)) { return Unauthorized(); }
    return Ok(Do());
}`],
  ["abort_unless with an alternative lets the alternative in", "brace", `function (Request $request) {
        abort_unless(auth()->check() || config('app.public'), 403);
        return 1;
    }`],
  ["an authorize-named call with 'not found' is only a name", "brace", `public IActionResult X(Guid id) {
    if (!_service.IsAuthorizedForTenant(id)) { return NotFound(); }
    return Ok(Do());
}`],
  ["a session every visitor is given, and a socket closed", "brace", `webSocket("/ws") {
                val session = call.sessions.get<ChatSession>()
                if (session == null) {
                    close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "No session"))
                    return@webSocket
                }
                serve(session)
            }`],
  ["CTFd's email confirmation: a branch that marks the account verified and returns, before the sign-in check", "python", `def confirm(data=None):
    if data and request.method == "GET":
        user_email = verify_email_confirm_token(data)
        user = Users.query.filter_by(email=user_email).first_or_404()
        user.verified = True
        db.session.commit()
        return redirect(url_for("auth.login"))

    if current_user.authed() is False:
        return redirect(url_for("auth.login"))
    return render_template("confirm.html")`],
  ["work at the top level before the guard", "python", `def publish():
    db.session.commit()
    if not current_user.is_authenticated:
        abort(401)
    return "ok"`],
  ["a field written before the guard", "brace", `public IActionResult Confirm() {
    _user.Verified = true;
    if (!User.Identity.IsAuthenticated) { return Unauthorized(); }
    return Ok();
}`],
  ["an earlier arm of the chain does the work, the guard is the else-if", "brace", `async (req, res) => {
  if (req.query.token) {
    await db.confirm(req.query.token);
    return res.redirect("/");
  } else if (!req.session.user) {
    return res.status(401).end();
  }
  res.json(await db.all());
}`],
  ["a read-named call that writes", "python", `def join():
    get_or_create(Member, email=request.form["email"])
    if not current_user.is_authenticated:
        abort(401)
    return "ok"`],
  ["microblog's reset request: the signed-in caller is the one turned away", "python", `def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    return render_template('auth/reset_password_request.html', form=form)`],
  ["a session present is refused, not a session missing", "brace", `get("/login") {
        val session = call.sessions.get<UserSession>()
        if (session != null) {
            return@get call.respondRedirect("/")
        }
        call.respond(loginPage())
    }`],
  ["a token that matches is refused", "python", `def item():
    token = request.headers.get("X-Api-Key")
    if token == os.environ["API_KEY"]:
        abort(403)
    return "ok"`],
];

for (const [name, family, body, want] of YES) {
  test(`credited: ${name}`, () => assert.equal(handlerGuard([body], family), want));
}
for (const [name, family, body] of NO) {
  test(`not credited: ${name}`, () => assert.equal(handlerGuard([body], family), null));
}

// --- through the whole check, one reader at a time ------------------------------------------------

function project(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "auth-handler-"));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}

function routesOf(files) {
  const dir = project(files);
  try {
    const r = checkAuthentication(dir);
    return Object.fromEntries(r.routes.map((x) => [`${x.method} ${x.route}`, x.protectedBy]));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const LANGUAGES = {
  "Python (Flask, two decorators)": {
    "app.py": `from flask import Flask, request, abort
import hmac, os
app = Flask(__name__)

@app.get("/admin")
@cache.cached(timeout=60)
def admin():
    if not hmac.compare_digest(request.headers.get("X-Admin-Token", ""), os.environ["ADMIN_TOKEN"]):
        abort(403)
    return "ok"

@app.get("/open")
def open_page():
    return "ok"
`,
  },
  "JavaScript (Express)": {
    "app.js": `const app = require("express")();
app.get("/admin", (req, res) => {
  if (!req.session.userId) return res.status(401).end();
  res.send("ok");
});
app.get("/open", (req, res) => res.send("ok"));
`,
  },
  "Go (net/http)": {
    "main.go": `package main
func main() {
	http.HandleFunc("/admin", admin)
	http.HandleFunc("/open", open)
}
func admin(w http.ResponseWriter, r *http.Request) {
	if !users.IsSignedIn(r) {
		http.Error(w, "sign in", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("ok"))
}
func open(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`,
  },
  "Java (Spring)": {
    "src/main/java/a/AdminController.java": `package a;
@RestController
public class AdminController {
  @GetMapping("/admin")
  public ResponseEntity<String> admin(@RequestHeader("X-Token") String token) {
    if (!MessageDigest.isEqual(token.getBytes(), adminToken.getBytes())) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    return ResponseEntity.ok("ok");
  }
  @GetMapping("/open")
  public String open() { return "ok"; }
}
`,
  },
  "Ruby (Sinatra)": {
    "app.rb": `require 'sinatra'
get '/admin' do
  halt 401 unless session[:user_id]
  'ok'
end
get '/open' do
  'ok'
end
`,
  },
  "C# (a controller, and a minimal API)": {
    "Api/AdminController.cs": `[ApiController]
public class AdminController : ControllerBase
{
    [HttpGet("/admin")]
    public IActionResult Admin([FromQuery] string key)
    {
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(key), _expected))
        {
            return Unauthorized();
        }
        return Ok();
    }
    [HttpGet("/open")]
    public IActionResult Open() => Ok();
}
`,
    "Api/Program.cs": `var app = WebApplication.Create(args);
app.MapGet("/minimal-admin", (HttpContext ctx) =>
{
    if (!ctx.User.Identity.IsAuthenticated) { return Results.Unauthorized(); }
    return Results.Ok();
});
app.MapGet("/minimal-open", () => Results.Ok());
`,
  },
  "PHP (Laravel closure and controller, Symfony action)": {
    "routes/web.php": `<?php
Route::post('/hook', function (Request $request) {
    abort_unless(hash_equals(config('services.hook.secret'), (string) $request->header('X-Hook-Token')), 403);
    return 'ok';
});
Route::get('/report', [ReportController::class, 'show']);
Route::get('/open', fn () => 'ok');
`,
    "app/Http/Controllers/ReportController.php": `<?php
class ReportController extends Controller
{
    public function show(Request $request)
    {
        if (!Auth::check()) {
            abort(401);
        }
        return view('report');
    }
}
`,
    "src/Controller/AdminController.php": `<?php
class AdminController extends AbstractController
{
    #[Route('/sf-admin', methods: ['GET'])]
    public function index(): Response
    {
        if (!$this->getUser()) {
            throw new AccessDeniedException();
        }
        return new Response('ok');
    }
    #[Route('/sf-open', methods: ['GET'])]
    public function open(): Response
    {
        return new Response('ok');
    }
}
`,
  },
  "Kotlin (Spring and Ktor)": {
    "src/main/kotlin/a/Admin.kt": `package a
@RestController
class Admin {
    @GetMapping("/admin")
    fun admin(principal: Principal?): String {
        if (principal == null) throw ResponseStatusException(HttpStatus.UNAUTHORIZED)
        return "ok"
    }
    @GetMapping("/open")
    fun open(): String = "ok"
}
`,
    "src/main/kotlin/a/Routes.kt": `package a
fun Application.routes() {
    routing {
        get("/ktor-admin") {
            val session = call.sessions.get<UserSession>() ?: return@get call.respond(HttpStatusCode.Unauthorized)
            call.respondText(session.name)
        }
        get("/ktor-open") {
            call.respondText("ok")
        }
    }
}
`,
  },
};

for (const [language, files] of Object.entries(LANGUAGES)) {
  test(`${language}: a guarded handler is credited, its neighbour is not`, () => {
    const routes = routesOf(files);
    const guarded = Object.entries(routes).filter(([k]) => /admin|hook|report/.test(k));
    const open = Object.entries(routes).filter(([k]) => /open/.test(k));
    assert.ok(guarded.length >= 1 && open.length >= 1, JSON.stringify(routes));
    for (const [k, by] of guarded) assert.match(String(by), /in the handler$/, `${k}: ${by}`);
    for (const [k, by] of open) assert.equal(by, null, `${k} must stay open`);
  });
}

// [AllowAnonymous] says the framework requires no sign-in. Bitwarden's invite-token route declares it
// and validates the token in the action; the first version skipped anonymous routes and missed it.
test("a route declared anonymous is credited for a check in its handler, and stays marked open without one", () => {
  const routes = routesOf({
    "Api/InviteController.cs": `[Authorize]
public class InviteController : ControllerBase
{
    [AllowAnonymous]
    [HttpGet("/invite")]
    public IActionResult Get([FromQuery] string token)
    {
        if (!_tokens.ValidateInviteToken(token)) { throw new NotFoundException(); }
        return Ok();
    }
    [AllowAnonymous]
    [HttpGet("/invite-open")]
    public IActionResult Open() => Ok();
}
`,
  });
  assert.equal(routes["GET /invite"], "a secret checked in the handler");
  assert.equal(routes["GET /invite-open"], null);
});

test("a credited route is listed for a person to confirm, and an open one still blocks", () => {
  const dir = project(LANGUAGES["Python (Flask, two decorators)"]);
  try {
    const r = authenticationFailures(dir);
    assert.match(r.advisories.join("\n"), /^authentication: 1 route\(s\) count as protected by a check inside the handler — GET \/admin \(app\.py:5, a secret checked in the handler\)\./m);
    assert.match(r.failures.join("\n"), /1 of 2 endpoint\(s\) accept requests from anyone who can reach the service — GET \/open/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The Go reader took a route's handler names from the text after its path up to the first `);`,
// which Go does not write -- so a route read the next lines too, and was credited with the guard of
// the route declared below it.
test("a Go route is not credited with its neighbour's guard", () => {
  const routes = routesOf({
    "main.go": `package main
func main() {
	m.Post("/open", openHandler)
	m.Post("/admin", adminHandler)
}
func openHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != os.Getenv("ADMIN_TOKEN") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write([]byte("ok"))
}
`,
  });
  assert.equal(routes["POST /open"], null);
  assert.ok(routes["POST /admin"], JSON.stringify(routes));
});
