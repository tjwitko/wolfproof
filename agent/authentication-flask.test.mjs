import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { checkAuthentication, authenticationFailures } from "./authentication.mjs";

// Flask's own ways of protecting a view (agent/authentication-flask.mjs). Each case is a small app and
// what must protect each of its routes -- null where nothing does. The ones that must stay open are
// the half that matters: crediting protection that does not run is the dangerous direction.

function run(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "flask-"));
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

const verdicts = (report) => Object.fromEntries(report.routes.map((r) => [`${r.method} ${r.route}`, r.protectedBy]));

test("Flask-Login's decorator under the route protects it; a view without one stays open", () => {
  const files = {
    "app.py": "from flask import Flask\nfrom flask_login import login_required\n\napp = Flask(__name__)\n\n\n@app.get(\"/reports\")\n@login_required\ndef reports():\n    return []\n\n\n@app.get(\"/about\")\ndef about():\n    return \"about\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": "@login_required from flask_login",
    "GET /about": null
  });
});

test("the Flask tutorial's own login_required counts, because the function it wraps in redirects a caller without a user", () => {
  const files = {
    "flaskr/auth.py": "import functools\n\nfrom flask import Blueprint, g, redirect, url_for\n\nbp = Blueprint(\"auth\", __name__, url_prefix=\"/auth\")\n\n\ndef login_required(view):\n    @functools.wraps(view)\n    def wrapped_view(**kwargs):\n        if g.user is None:\n            return redirect(url_for(\"auth.login\"))\n        return view(**kwargs)\n\n    return wrapped_view\n\n\n@bp.before_app_request\ndef load_logged_in_user():\n    g.user = None\n",
    "flaskr/blog.py": "from flask import Blueprint\n\nfrom flaskr.auth import login_required\n\nbp = Blueprint(\"blog\", __name__)\n\n\n@bp.route(\"/create\", methods=(\"GET\", \"POST\"))\n@login_required\ndef create():\n    return \"created\"\n\n\n@bp.route(\"/\")\ndef index():\n    return \"posts\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "ROUTE /create": "the @login_required decorator, which refuses the caller",
    "ROUTE /": null
  });
});

test("an app's before_request hook protects its routes, except the endpoint it lets through", () => {
  const files = {
    "app.py": "from flask import Flask, abort, request, session\n\napp = Flask(__name__)\n\n\n@app.before_request\ndef require_login():\n    if request.endpoint in (\"about\", \"static\"):\n        return\n    if \"user_id\" not in session:\n        abort(401)\n\n\n@app.get(\"/reports\")\ndef reports():\n    return []\n\n\n@app.get(\"/about\")\ndef about():\n    return \"about\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": "a before_request hook (app.py:6)",
    "GET /about": null
  });
});

test("a blueprint's hook protects that blueprint's routes and no other's", () => {
  const files = {
    "admin.py": "from flask import Blueprint, abort, session\n\nbp = Blueprint(\"admin\", __name__, url_prefix=\"/admin\")\n\n\n@bp.before_request\ndef require_admin():\n    if not session.get(\"admin\"):\n        abort(403)\n\n\n@bp.get(\"/stats\")\ndef stats():\n    return \"stats\"\n",
    "public.py": "from flask import Blueprint\n\nbp = Blueprint(\"public\", __name__)\n\n\n@bp.get(\"/reports\")\ndef reports():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /stats": "a before_request hook (admin.py:6)",
    "GET /reports": null
  });
});

test("@jwt_required() protects; @jwt_required(optional=True) does not", () => {
  const files = {
    "app.py": "from flask import Flask\nfrom flask_jwt_extended import jwt_required\n\napp = Flask(__name__)\n\n\n@app.get(\"/reports\")\n@jwt_required()\ndef reports():\n    return []\n\n\n@app.get(\"/feed\")\n@jwt_required(optional=True)\ndef feed():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": "@jwt_required from flask_jwt_extended",
    "GET /feed": null
  });
});

test("Flask-HTTPAuth's @auth.login_required protects; optional=True does not", () => {
  const files = {
    "app.py": "from flask import Flask\nfrom flask_httpauth import HTTPTokenAuth\n\napp = Flask(__name__)\nauth = HTTPTokenAuth(scheme=\"Bearer\")\n\n\n@app.get(\"/reports\")\n@auth.login_required\ndef reports():\n    return []\n\n\n@app.get(\"/feed\")\n@auth.login_required(optional=True)\ndef feed():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": "@auth.login_required from flask_httpauth",
    "GET /feed": null
  });
});

test("Flask-Security's decorators protect", () => {
  const files = {
    "app.py": "from flask import Flask\nfrom flask_security import auth_required, roles_required\n\napp = Flask(__name__)\n\n\n@app.get(\"/reports\")\n@auth_required(\"token\", \"session\")\ndef reports():\n    return []\n\n\n@app.get(\"/admin\")\n@roles_required(\"admin\")\ndef admin():\n    return \"admin\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": "@auth_required from flask_security",
    "GET /admin": "@roles_required from flask_security"
  });
});

test("a decorator above the route decorator wraps a function Flask never calls", () => {
  const files = {
    "app.py": "from flask import Flask\nfrom flask_login import login_required\n\napp = Flask(__name__)\n\n\n@login_required\n@app.get(\"/reports\")\ndef reports():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": null
  });
});

test("a project's own decorator named login_required that refuses nobody protects nothing", () => {
  const files = {
    "app.py": "import functools\nimport logging\n\nfrom flask import Flask\n\napp = Flask(__name__)\n\n\ndef login_required(view):\n    @functools.wraps(view)\n    def wrapped(**kwargs):\n        logging.info(\"visit\")\n        return view(**kwargs)\n\n    return wrapped\n\n\n@app.get(\"/reports\")\n@login_required\ndef reports():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": null
  });
});

test("a hook that lets requests through on a condition this cannot read credits nothing", () => {
  const files = {
    "app.py": "from flask import Flask, abort, session\n\napp = Flask(__name__)\n\n\ndef is_public():\n    return True\n\n\n@app.before_request\ndef require_login():\n    if is_public():\n        return\n    if \"user_id\" not in session:\n        abort(401)\n\n\n@app.get(\"/reports\")\ndef reports():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": null
  });
});

test("a hook that loads the user and refuses nobody protects nothing", () => {
  const files = {
    "app.py": "from flask import Flask, g, session\n\napp = Flask(__name__)\n\n\n@app.before_request\ndef load_user():\n    g.user = session.get(\"user_id\")\n\n\n@app.get(\"/reports\")\ndef reports():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": null
  });
});

test("a blueprint's hook in its package __init__ reaches the views that import it, and not a blueprint of the same name elsewhere", () => {
  const files = {
    "app/api/views.py": "from flask import Blueprint\n\nmain = Blueprint(\"api\", __name__)\n\n\n@main.route(\"/open\")\ndef open_route():\n    return \"o\"\n",
    "app/main/__init__.py": "from flask import Blueprint, abort\nfrom flask_login import current_user\n\nmain = Blueprint(\"main\", __name__)\n\n\n@main.before_request\ndef require_login():\n    if not current_user.is_authenticated:\n        abort(401)\n\n\nfrom . import views\n",
    "app/main/views.py": "from . import main\n\n\n@main.route(\"/dashboard\")\ndef dashboard():\n    return \"d\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "ROUTE /dashboard": "a before_request hook (app/main/__init__.py:7)",
    "ROUTE /open": null
  });
});

test("two blueprints called bp are two blueprints", () => {
  const files = {
    "admin.py": "from flask import Blueprint, abort, session\n\nbp = Blueprint(\"admin\", __name__)\n\n\n@bp.before_request\ndef require_admin():\n    if not session.get(\"admin\"):\n        abort(403)\n",
    "public.py": "from flask import Blueprint\n\nbp = Blueprint(\"public\", __name__)\n",
    "routes.py": "from public import bp\n\n\n@bp.get(\"/reports\")\ndef reports():\n    return []\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": null
  });
});

test("an app factory's hook protects the routes under the app's directory, not another app's", () => {
  const files = {
    "app/__init__.py": "from flask import Flask, redirect, session, url_for\n\n\ndef create_app():\n    app = Flask(__name__)\n\n    @app.before_request\n    def require_login():\n        if session.get(\"user_id\") is None:\n            return redirect(url_for(\"login\"))\n\n    from .views import bp\n    app.register_blueprint(bp)\n    return app\n",
    "app/views.py": "from flask import Blueprint\n\nbp = Blueprint(\"views\", __name__)\n\n\n@bp.get(\"/reports\")\ndef reports():\n    return []\n",
    "other/app.py": "from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.get(\"/elsewhere\")\ndef elsewhere():\n    return \"e\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /reports": "a before_request hook (app/__init__.py:7)",
    "GET /elsewhere": null
  });
});

test("an aliased import and the module form both count", () => {
  const files = {
    "app.py": "import flask_login\nfrom flask import Flask\nfrom flask_login import login_required as needs_login\n\napp = Flask(__name__)\n\n\n@app.get(\"/a\")\n@needs_login\ndef a():\n    return \"a\"\n\n\n@app.get(\"/b\")\n@flask_login.login_required\ndef b():\n    return \"b\"\n"
  };
  assert.deepEqual(verdicts(run(files, checkAuthentication)), {
    "GET /a": "@needs_login from flask_login",
    "GET /b": "@flask_login.login_required"
  });
});

test("the blocking finding lists only the route the hook lets through, and names the Flask fixes", () => {
  const { failures } = run(
    {
      "app.py":
        'from flask import Flask, abort, request, session\n\napp = Flask(__name__)\n\n\n@app.before_request\ndef require_login():\n' +
        '    if request.endpoint in ("about", "static"):\n        return\n    if "user_id" not in session:\n        abort(401)\n\n\n' +
        '@app.get("/reports")\ndef reports():\n    return []\n\n\n@app.get("/about")\ndef about():\n    return "about"\n',
    },
    authenticationFailures
  );
  const open = failures.find((f) => /accept requests from anyone/.test(f));
  assert.match(open, /1 of 2 endpoint\(s\)/);
  assert.match(open, /GET \/about \(app\.py:19\)/);
  assert.match(open, /`@login_required` \(Flask-Login\)/);
});

test("a hook's path exemptions open the routes they match, and a prefixed blueprint's routes", () => {
  const hook =
    "@app.before_request\ndef require_login():\n" +
    '    if (request.path.startswith("/public") or (request.path == "/ping")):\n        return\n' +
    '    if "user_id" not in session:\n        abort(401)\n';
  const report = run(
    {
      "app.py":
        "from flask import Flask, abort, request, session\n\napp = Flask(__name__)\n\n\n" + hook +
        '\n\n@app.get("/public/docs")\ndef docs():\n    return "d"\n\n\n@app.get("/reports")\ndef reports():\n    return []\n',
      // Registered nowhere that is found, so its full path is not known: "/stats" may well be "/public/stats".
      "admin.py": 'from flask import Blueprint\n\nbp = Blueprint("admin", __name__, url_prefix="/public")\n\n\n@bp.get("/stats")\ndef stats():\n    return "s"\n',
    },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), {
    "GET /stats": null,
    "GET /public/docs": null,
    "GET /reports": "a before_request hook (app.py:6)",
  });
});

// flask-restx declares the route on a Resource class, and each method has its own decorators. The
// reader read on to the first def, so the class was judged by its first method: a guarded `get`
// credited an open `post`. CTFd declares its whole API this way.
test("a route on a class is not judged by its first method's decorators or body", () => {
  const report = run(
    {
      "api.py":
        "from flask import abort, session\nfrom flask_login import login_required\nfrom flask_restx import Namespace, Resource\n\n" +
        'ns = Namespace("reports")\n\n\n@ns.route("")\nclass Reports(Resource):\n    @login_required\n    def get(self):\n        return []\n\n' +
        "    def post(self):\n        return {}\n\n\n" +
        '@ns.route("/export")\nclass Export(Resource):\n    def get(self):\n        if "user_id" not in session:\n            abort(401)\n        return []\n\n' +
        "    def delete(self):\n        return {}\n",
    },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), { "ROUTE ": null, "ROUTE /export": null });
});

// --- flask-restx under a blueprint -----------------------------------------------------------------
// A flask-restx route is declared on a Namespace or the Api, never on the blueprint, so a blueprint's
// hook was not matched to it -- though Flask runs that hook for every route of an Api mounted on the
// blueprint. CTFd's shape: the blueprint, the Api and the hook in the package's __init__, each
// namespace in its own module, imported by its whole dotted path, beside a module of the same name.
const lineOf = (text, needle) => text.split("\n").findIndex((l) => l.includes(needle)) + 1;
const REFUSE = "    if not current_user.is_authenticated:\n        abort(401)\n";

test("a blueprint's hook protects the flask-restx routes of an Api mounted on it, across modules", () => {
  const init =
    "from flask import Blueprint, abort\nfrom flask_login import current_user\nfrom flask_restx import Api\n\n" +
    "from app.api.v1.users import users_namespace\nfrom .v1.teams import teams_namespace as teams\n\n" +
    'api = Blueprint("api", __name__, url_prefix="/api/v1")\nAPI_v1 = Api(\n    api,\n    doc=False,\n)\n' +
    'API_v1.add_namespace(users_namespace, "/users")\nAPI_v1.add_namespace(teams, "/teams")\n\n\n' +
    "@api.before_request\ndef require_login():\n" + REFUSE;
  const resource = (ns, cls) =>
    `from flask_restx import Namespace, Resource\n\n${ns} = Namespace("${cls.toLowerCase()}")\n\n\n` +
    `@${ns}.route("/<int:id>")\nclass ${cls}(Resource):\n    def delete(self, id):\n        return {}\n`;
  const report = run(
    {
      "app/api/__init__.py": init,
      "app/api/v1/users.py": resource("users_namespace", "Users"),
      "app/api/v1/teams.py": resource("teams_namespace", "Teams"),
      // The same names in other modules, read first: `app.admin.users` is not `app.api.v1.users`.
      "app/admin/users.py": resource("users_namespace", "LegacyUsers").replace("/<int:id>", "/legacy/<int:id>"),
      "app/admin/teams.py": resource("teams_namespace", "LegacyTeams").replace("/<int:id>", "/legacy-teams/<int:id>"),
    },
    checkAuthentication
  );
  const hook = `a before_request hook (app/api/__init__.py:${lineOf(init, "@api.before_request")})`;
  const byFile = Object.fromEntries(report.routes.map((r) => [r.file, r.protectedBy]));
  assert.deepEqual(byFile, {
    "app/api/v1/users.py": hook,
    "app/api/v1/teams.py": hook,
    "app/admin/users.py": null,
    "app/admin/teams.py": null,
  });
});

test("api.namespace(), init_app and Api(app=bp) mount an Api on the blueprint too", () => {
  const namespaced =
    "from flask import Blueprint, abort\nfrom flask_login import current_user\nfrom flask_restx import Api, Resource\n\n" +
    'bp = Blueprint("api", __name__)\napi = Api(doc=False)\napi.init_app(bp)\nns = api.namespace("things")\n\n\n' +
    "@bp.before_request\ndef require_login():\n" + REFUSE +
    '\n\n@ns.route("/things")\nclass Things(Resource):\n    def post(self):\n        return {}\n';
  const onApi =
    "from flask import Blueprint, abort\nfrom flask_login import current_user\nfrom flask_restx import Api, Resource\n\n" +
    'bp = Blueprint("reports", __name__)\napi = Api(app=bp)\n\n\n' +
    "@bp.before_request\ndef require_login():\n" + REFUSE +
    '\n\n@api.route("/reports")\nclass Reports(Resource):\n    def post(self):\n        return {}\n';
  const report = run({ "things.py": namespaced, "reports.py": onApi }, checkAuthentication);
  assert.deepEqual(verdicts(report), {
    "ROUTE /things": `a before_request hook (things.py:${lineOf(namespaced, "@bp.before_request")})`,
    "ROUTE /reports": `a before_request hook (reports.py:${lineOf(onApi, "@bp.before_request")})`,
  });
});

test("a flask-restx route stays open under another blueprint's hook, an Api it was never added to, or a hook that exempts by path or endpoint", () => {
  const head = "from flask import Blueprint, Flask, abort, request\nfrom flask_login import current_user\nfrom flask_restx import Api, Namespace, Resource\n\n";
  const route = (ns, p) => `\n\n@${ns}.route("${p}")\nclass C${p.replace(/\W/g, "")}(Resource):\n    def post(self):\n        return {}\n`;
  const report = run(
    {
      // The hook is on `admin`; the Api is on `public`.
      "other.py":
        head + 'admin = Blueprint("admin", __name__)\npublic = Blueprint("public", __name__)\napi = Api(public)\nns = Namespace("a")\napi.add_namespace(ns)\n\n\n' +
        "@admin.before_request\ndef require_login():\n" + REFUSE + route("ns", "/other"),
      // Never added to the Api.
      "unmounted.py":
        head + 'bp = Blueprint("b", __name__)\napi = Api(bp)\nns = Namespace("b")\n\n\n@bp.before_request\ndef require_login():\n' + REFUSE + route("ns", "/unmounted"),
      // The rule names the route's full path: the namespace's "/c", then its own "/bypath".
      "bypath.py":
        head + 'bp = Blueprint("c", __name__)\napi = Api(bp)\nns = Namespace("c")\napi.add_namespace(ns)\nmain = Flask(__name__)\nmain.register_blueprint(bp)\n\n\n' +
        '@bp.before_request\ndef require_login():\n    if request.path.startswith("/c/by"):\n        return\n' + REFUSE + route("ns", "/bypath"),
      // flask-restx names this Resource's endpoint `public_cbyendpoint` (`<namespace>_<class>`), and the
      // hook lets it through; the reader took the class's endpoint to be its first method's name.
      "app/byendpoint.py":
        head + 'app = Flask(__name__)\napi = Api(app)\nns = Namespace("public")\napi.add_namespace(ns)\n\n\n@app.before_request\ndef require_login():\n' +
        '    if request.endpoint in ("public_cbyendpoint", "auth.login"):\n        return\n' + REFUSE + route("ns", "/byendpoint"),
    },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), {
    "ROUTE /other": null,
    "ROUTE /unmounted": null,
    "ROUTE /bypath": null,
    "ROUTE /byendpoint": null,
  });
});

test("two services with the same module paths: each Api's namespaces are its own service's", () => {
  const init = (hook) =>
    "from flask import Blueprint, abort\nfrom flask_login import current_user\nfrom flask_restx import Api\n\n" +
    'from app.api.v1.users import users_namespace\n\napi = Blueprint("api", __name__)\nAPI = Api(api)\nAPI.add_namespace(users_namespace)\n' +
    (hook ? "\n\n@api.before_request\ndef require_login():\n" + REFUSE : "");
  const users = (p) => `from flask_restx import Namespace, Resource\n\nusers_namespace = Namespace("users")\n\n\n@users_namespace.route("${p}")\nclass Users(Resource):\n    def delete(self):\n        return {}\n`;
  const report = run(
    {
      "services/a/app/api/__init__.py": init(false),
      "services/a/app/api/v1/users.py": users("/a"),
      "services/b/app/api/__init__.py": init(true),
      "services/b/app/api/v1/users.py": users("/b"),
    },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), {
    "ROUTE /a": null,
    "ROUTE /b": `a before_request hook (services/b/app/api/__init__.py:${lineOf(init(true), "@api.before_request")})`,
  });
});

test("modules that import each other do not send the reader round in circles", () => {
  const report = run(
    {
      "a.py": "from b import ns\n\n\n@ns.route(\"/a\")\nclass A(Resource):\n    def post(self):\n        return {}\n",
      "b.py": "from flask import Blueprint, abort\nfrom flask_login import current_user\nfrom a import ns\n\nbp = Blueprint(\"b\", __name__)\n\n\n@bp.before_request\ndef require_login():\n" + REFUSE,
    },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), { "ROUTE /a": null });
});

test("a module path that matches under two roots both holding the importer is not resolved", () => {
  const init =
    "from flask import Blueprint, abort\nfrom flask_login import current_user\nfrom flask_restx import Api\n\n" +
    'from app.api.v1.users import users_namespace\n\napi = Blueprint("api", __name__)\nAPI = Api(api)\nAPI.add_namespace(users_namespace)\n' +
    "\n\n@api.before_request\ndef require_login():\n" + REFUSE;
  const users = (p) => `from flask_restx import Namespace, Resource\n\nusers_namespace = Namespace("users")\n\n\n@users_namespace.route("${p}")\nclass Users(Resource):\n    def delete(self):\n        return {}\n`;
  const report = run(
    { "x/app/api/v1/users.py": users("/outer"), "x/y/app/api/__init__.py": init, "x/y/app/api/v1/users.py": users("/inner") },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), { "ROUTE /outer": null, "ROUTE /inner": null });
});

// The same holds for a class on a plain blueprint (a MethodView under `@bp.route`, as flask-smorest
// declares them): its endpoint is not its first method's name.
test("a hook's endpoint rule reaches a class route on a blueprint, which stays open", () => {
  const report = run(
    {
      "views.py":
        "from flask import Blueprint, abort, request\nfrom flask.views import MethodView\nfrom flask_login import current_user\n\n" +
        'bp = Blueprint("b", __name__)\n\n\n@bp.before_request\ndef require_login():\n    if request.endpoint in ("b.Things",):\n        return\n' + REFUSE +
        '\n\n@bp.route("/things")\nclass Things(MethodView):\n    def post(self):\n        return {}\n',
    },
    checkAuthentication
  );
  assert.deepEqual(verdicts(report), { "ROUTE /things": null });
});

// --- the full path a hook's rule reads -------------------------------------------------------------
// `request.path` is the whole path, while the route decorator gives only its last part. A hook letting
// "/public" through was credited on a blueprint registered at `url_prefix="/public"`. The joins are
// Flask's: the prefix given to `register_blueprint`, else the one in `Blueprint(...)`; a nested
// blueprint's joined to its parent's; flask-restx's Api prefix and namespace path after them.
const byFile = (report) => Object.fromEntries(report.routes.map((r) => [r.file, r.protectedBy]));
const LOGIN = '    if "user_id" not in session:\n        abort(401)\n';
const view = (bp, p, extra = "") => `from flask import Blueprint\n\nbp = Blueprint("${bp}", __name__${extra})\n\n\n@bp.get("${p}")\ndef v():\n    return ""\n`;

test("a blueprint's url_prefix, from Blueprint() or register_blueprint(), is part of the path a hook's rule reads", () => {
  const app =
    "from flask import Flask, abort, request, session\n\nfrom public import bp as public_bp\nfrom . import admin  # noqa: E402\nfrom override import bp as override_bp  # noqa: E402\nimport staff  # noqa: E402\n\n" +
    'app = Flask(__name__)\napp.register_blueprint(public_bp, url_prefix="/public")\napp.register_blueprint(admin.bp)\n' +
    'app.register_blueprint(override_bp, url_prefix="/internal")\napp.register_blueprint(staff.bp, url_prefix="/staff")\n\n\n' +
    '@app.before_request\ndef require_login():\n    if request.path.startswith("/public"):\n        return\n' + LOGIN +
    '\n\n@app.get("/public-key")\ndef key():\n    return ""\n';
  const hook = `a before_request hook (app.py:${lineOf(app, "@app.before_request")})`;
  const report = run(
    {
      "app.py": app,
      // Registered at "/public": "/public/stats", which the hook lets through.
      "public.py": view("public", "/stats"),
      // Its own prefix: "/admin/stats".
      "admin.py": view("admin", "/stats", ', url_prefix="/admin"'),
      // The registration's prefix replaces the blueprint's: "/internal/stats", not "/public/stats".
      "override.py": view("override", "/stats", ', url_prefix="/public"'),
      "staff.py": view("staff", "/stats"),
    },
    checkAuthentication
  );
  assert.deepEqual(byFile(report), {
    // `startswith` compares strings, not segments: "/public-key" starts with "/public".
    "app.py": null,
    "public.py": null,
    "admin.py": hook,
    "override.py": hook,
    "staff.py": hook,
  });
});

test("nested blueprints join their prefixes with one slash, and a project's subclass of Flask is an app", () => {
  const app =
    "from flask import Blueprint, Flask, abort, request, session\n\n\nclass Portal(Flask):\n    pass\n\n\n" +
    'app = Portal(__name__)\napi = Blueprint("api", __name__, url_prefix="/api/")\npublic = Blueprint("public", __name__, url_prefix="/public")\n' +
    'v1 = Blueprint("v1", __name__)\napi.register_blueprint(public)\napi.register_blueprint(v1, url_prefix="/v1/")\napp.register_blueprint(api)\n\n\n' +
    '@app.before_request\ndef require_login():\n    if request.path.startswith("/api/public/") or request.path == "/api/v1/things":\n        return\n' + LOGIN +
    '\n\n@public.get("/docs")\ndef docs():\n    return ""\n\n\n@v1.get("/things")\ndef things():\n    return ""\n\n\n@api.get("/public")\ndef listing():\n    return ""\n';
  const hook = `a before_request hook (app.py:${lineOf(app, "@app.before_request")})`;
  const report = run({ "app.py": app }, checkAuthentication);
  // Each join drops the doubled "/": "/api/" and "/v1/" make "/api/v1/things".
  assert.deepEqual(verdicts(report), { "GET /docs": null, "GET /things": null, "GET /public": hook });
});

test("where a prefix cannot be read, a hook's path rule is taken to reach the route", () => {
  const app =
    "from flask import Flask, abort, request, session\n\nfrom a import bp as a_bp\nfrom b import bp as b_bp\nfrom c import bp as c_bp\nfrom f import bp as f_bp\nfrom g import bp as g_bp\nfrom h import bp as h_bp\nfrom i import bp as i_bp\nfrom k import bp as k_bp\nfrom n import bp as n_bp\n\n" +
    'PREFIX = "/a"\napp = Flask(__name__)\napp.register_blueprint(a_bp, url_prefix=PREFIX)\napp.register_blueprint(a_bp, url_prefix="/z", name="z")\nfor blueprint in discover(b_bp):\n    app.register_blueprint(blueprint)\n\n\n' +
    "def init_app(target):\n    target.register_blueprint(c_bp)\n\n\napp.register_blueprint(c_bp, url_prefix=\"/c2\")\napp.register_blueprint(f_bp)\n\n\n" +
    "for blueprint in [i_bp][1:]:\n    app.register_blueprint(blueprint)\nthing = build()\nthing.register_blueprint(k_bp)\n\n\n" +
    "def make():\n    def later():\n        return n_bp\n\n    return None\n\n\nfor blueprint in [make()]:\n    app.register_blueprint(blueprint)\n\n\n" +
    "def attach(target):\n    target.register_blueprint(g_bp)\n\n\nattach(app)\nSETUP = [attach]\n\n\n" +
    "def outer():\n    def inner(target):\n        target.register_blueprint(h_bp)\n\n    inner(app)\n\n\n" +
    '@app.before_request\ndef require_login():\n    if request.path == "/nothing-here":\n        return\n' + LOGIN +
    '\n\n@app.get("/d")\ndef d():\n    return ""\n';
  const report = run(
    {
      "app.py": app,
      "a.py": view("a", "/a"), // one of its two prefixes is not a literal
      "f.py": view("f", "/f", ", url_prefix=settings.PREFIX"), // nor is its own
      "b.py": view("b", "/b"), // registered in a loop over something not written out
      "c.py": view("c", "/c"), // also registered on a parameter of a function never called, which may be called from outside
      "g.py": view("g", "/g"), // ... of a function also passed as a value, so called with anything
      "h.py": view("h", "/h"), // ... of a nested function, whose calls are not looked for
      "i.py": view("i", "/i"), // in a loop over a slice, not the list written out
      "k.py": view("k", "/k"), // on something not traced to an app or a blueprint
      "n.py": view("n", "/n"), // returned by a function nested in the one called, not by it
      "e.py": view("e", "/e"), // registered nowhere
    },
    checkAuthentication
  );
  assert.deepEqual(byFile(report), {
    "app.py": `a before_request hook (app.py:${lineOf(app, "@app.before_request")})`,
    "a.py": null,
    "b.py": null,
    "c.py": null,
    "e.py": null,
    "f.py": null,
    "g.py": null,
    "h.py": null,
    "i.py": null,
    "k.py": null,
    "n.py": null,
  });
});

test("a blueprint registered by a helper, in a loop, or made by a factory has a known prefix, as redash registers its own", () => {
  const app =
    "from flask import Flask, abort, request, session\n\nfrom portal import handlers\nfrom portal.login import init_app as init_login\n\n\n" +
    "def create_app():\n    app = Flask(__name__)\n    handlers.init_app(app)\n    init_login(app)\n\n" +
    '    @app.before_request\n    def require_login():\n        if request.path.startswith("/public"):\n            return\n' +
    LOGIN.replace(/^/gm, "    ").replace(/ +$/, "") + "\n    return app\n";
  const handlers =
    'from flask import Blueprint\n\nroutes = Blueprint("routes", __name__)\napi = Blueprint("api", __name__)\ndocs = Blueprint("docs", __name__)\nEXTRA = [docs]\n\n\n' +
    '@routes.get("/status")\ndef status():\n    return ""\n\n\n@api.get("/public")\ndef listing():\n    return ""\n\n\n@docs.get("/public")\ndef manual():\n    return ""\n\n\n' +
    'def mount(app, bp):\n    app.register_blueprint(bp, url_prefix="/v2")\n\n\n' +
    "def init_app(app):\n    app.register_blueprint(routes)\n    mount(app, bp=api)\n    for bp in EXTRA:\n        app.register_blueprint(bp, url_prefix=\"/v3\")\n";
  const login =
    'from flask import Blueprint\n\nfrom portal import oauth\n\nsaml = Blueprint("saml", __name__)\n\n\n@saml.get("/saml")\ndef sso():\n    return ""\n\n\n' +
    "def init_app(app):\n    for blueprint in [\n        oauth.create_blueprint(app),  # off unless configured\n        saml,\n    ]:\n        if blueprint:\n            app.register_blueprint(blueprint)\n";
  const oauth =
    "from flask import Blueprint\n\n\ndef create_blueprint(app):\n    if not app.config.get(\"OAUTH\"):\n        return None\n" +
    '    blueprint = Blueprint("oauth", __name__, url_prefix="/sso")\n\n    @blueprint.get("/public")\n    def callback():\n        return ""\n\n    return blueprint\n';
  const hook = `a before_request hook (portal/app.py:${lineOf(app, "@app.before_request")})`;
  const report = run(
    { "portal/__init__.py": "", "portal/app.py": app, "portal/handlers.py": handlers, "portal/login.py": login, "portal/oauth.py": oauth },
    checkAuthentication
  );
  // Read by name alone, none of these was found registered, so the rule was taken to reach them all.
  // "/v2/public", "/v3/public" and "/sso/public" do not start with "/public": their prefixes close them.
  assert.deepEqual(verdicts(report), { "GET /status": hook, "GET /public": hook, "GET /saml": hook });
  assert.equal(report.routes.filter((r) => r.protectedBy === hook).length, 5);
});

test("a parameter is what its function is called with, not a module-level name it shadows, and each call pairs its own arguments", () => {
  const app =
    "from flask import Blueprint, Flask, abort, request, session\n\nfrom w import bp as w_bp\nfrom x import bp as x_bp\nfrom y import bp as y_bp\n\n" +
    'app = Flask(__name__)\nsub = Blueprint("sub", __name__, url_prefix="/sub")\n\n\n' +
    "def attach(app, bp):\n    app.register_blueprint(bp)\n\n\n" +
    "def put(bp, target=app):\n    target.register_blueprint(bp)\n\n\ndef setup(app):\n    put(w_bp)\n\n\n" +
    "attach(sub, x_bp)\nattach(app, y_bp)\nsetup(sub)\napp.register_blueprint(sub)\n\n\n" +
    '@app.before_request\ndef require_login():\n    if request.path.startswith("/sub"):\n        return\n' + LOGIN;
  const hook = `a before_request hook (app.py:${lineOf(app, "@app.before_request")})`;
  const report = run({ "app.py": app, "w.py": view("w", "/w"), "x.py": view("x", "/x"), "y.py": view("y", "/y") }, checkAuthentication);
  // x is served at "/sub/x", which the rule lets through; read as the module's app, it was "/x" and
  // credited. y is served at "/y" alone: the call passing it passes the app, not `sub`. w is put on
  // the app by a default, read where `put` is defined: inside `setup`, `app` is `sub`.
  assert.deepEqual(byFile(report), { "w.py": hook, "x.py": null, "y.py": hook });
});

// Redash writes 19 rules as `org_scoped_rule("/login")`, none of which was found as a route. Each pair
// here differs only in whether the hook lets its path through, so a path read wrong flips a verdict.
test("a route whose rule is a call is found, and its full paths are what the call can return", () => {
  const settings = 'import os\n\nMULTI_ORG = os.environ.get("MULTI_ORG") == "1"\nPREFIX = os.environ.get("PREFIX", "/env")\n';
  const base =
    "import settings\n\n\ndef scoped(rule):\n    if settings.MULTI_ORG:\n        return \"/<org_slug>{}\".format(rule)\n    return rule\n\n\n" +
    'def versioned(rule, version="v1"):\n    return f"/api/{version}{rule}"\n\n\n' +
    'def joined(rule):\n    return "/x" + rule + "/"\n\n\n' +
    'def nested_rule(rule):\n    return scoped("/n" + rule)\n\n\n' +
    'def numbered(rule):\n    return "/{0}/{name}{1}".format("num", rule, name="k")\n\n\n' +
    "def unknowable(rule):\n    return settings.PREFIX + rule\n\n\n" +
    'def paren(rule):\n    return ("/p" + rule)\n\n\n' +
    'def dflt(rule="/d0"):\n    return rule\n\n\n' +
    'def pair(rule):\n    return "{}{}".format("/t", rule)\n\n\n' +
    "def half(rule):\n    if settings.MULTI_ORG:\n        return settings.PREFIX + rule\n    return rule\n";
  const get = (rule, name) => `\n\n@app.get(${rule})\ndef ${name}(**kw):\n    return ""\n`;
  const app =
    "from flask import Flask, abort, request, session\nfrom flask_restx import Api, Resource\n\nimport base\nimport settings\n" +
    "from base import dflt, half, joined, numbered, pair, paren, scoped, unknowable, versioned\n\n" +
    'app = Flask(__name__)\napi = Api(app, doc=False)\nARGS = ("/sp",)\n' +
    "HINT = 'decorate it, @app.route(rule, methods=[\"POST\"])'\n\n\n" +
    "@app.before_request\ndef require_login():\n" +
    '    if request.path in ("/open", "/acme/w9", "/api/v2/v", "/x/j/", "/num/k/m", "/n/st", "/raw", "/p/1", "/r1", "/t/a1", "/p/3", "/kw", "/b2"):\n        return\n' + LOGIN +
    get('scoped("/w")', "w") + get('scoped("/open")', "open_") + get('scoped("/w9")', "w9") +
    get('versioned("/v", version="v2")', "v") + get('versioned(rule="/w1")', "w1") +
    get('joined("/j")', "j") + get('joined("/j2")', "j2") + get('numbered("/m")', "m") + get('numbered("/m2")', "m2") +
    get('base.nested_rule("/st")', "st") + get('base.nested_rule("/q")', "q") + get('r"/raw"', "raw") +
    get('unknowable("/k")', "k") + get('settings.PREFIX + "/k2"', "k2") + get("scoped(*ARGS)", "sp") +
    get('paren("/1")', "p1") + get('paren("/2")', "p2") + get("dflt()", "d0") + get("dflt(*ARGS)", "d1") + get('half("/h")', "h") +
    get('pair("/a1")', "t1") + get('pair("/a2")', "t2") + get('rule=scoped("/kw")', "kw") +
    get('"/b1" if settings.MULTI_ORG else "/b2"', "bb") + get('"/c1" if settings.MULTI_ORG else "/c2"', "cc") + get('"/x9" + settings.PREFIX', "x9") +
    get('"/d1" if settings.MULTI_ORG else settings.PREFIX', "dd") + get('rule="/kw2"', "kw2") +
    '\n\n@api.route(scoped("/r1"))\nclass R1(Resource):\n    def get(self, **kw):\n        return {}\n' +
    '\n\n@api.route(scoped("/r2"))\nclass R2(Resource):\n    def get(self, **kw):\n        return {}\n' +
    '\n\n@api.route(paren("/3"))\nclass R3(Resource):\n    def get(self):\n        return {}\n' +
    '\n\n@api.route(unknowable("/r4"))\nclass R4(Resource):\n    def get(self):\n        return {}\n' +
    '\n\n@app.get(\n    scoped("/ml"),\n)\ndef ml():\n    return ""\n';
  const report = run({ "app.py": app, "base.py": base, "settings.py": settings }, checkAuthentication);
  const hook = `a before_request hook (app.py:${lineOf(app, "@app.before_request")})`;
  // Checked against Flask 3.1.3, with MULTI_ORG unset and set: every path computed here is one Flask
  // serves, and the routes whose paths are not computed are those built from PREFIX or a spread.
  // Each decorator is one route: none is read by both route patterns.
  assert.equal(report.routes.length, Object.keys(verdicts(report)).length);
  assert.deepEqual(verdicts(report), {
    "GET /w": hook,
    "GET /open": null,
    "GET /w9": null, // "/<org_slug>/w9" when MULTI_ORG is set
    "GET /v": null, // "/api/v2/v"
    "GET /w1": hook, // "/api/v1/w1", with the default read
    "GET /j": null, // "/x/j/"
    "GET /j2": hook,
    "GET /m": null, // "/num/k/m"
    "GET /m2": hook,
    "GET /st": null, // "/n/st", through a second helper
    "GET /q": hook,
    "GET /raw": null,
    "GET /k": null, // not known, so the rule is taken to reach it
    'GET settings.PREFIX + "/k2"': null,
    "GET scoped(*ARGS)": null,
    "GET /ml": hook,
    "GET /1": null, // "/p/1", in brackets
    "GET /2": hook,
    "GET dflt()": hook, // "/d0", the default
    "GET dflt(*ARGS)": null, // a spread may fill the parameter
    "GET /h": null, // one return is not known
    "ROUTE /r1": null, // a flask-restx route, "/r1"
    "ROUTE /r2": hook,
    "ROUTE /3": null, // "/p/3"
    "ROUTE /r4": null,
    "GET /a1": null, // "/t/a1"
    "GET /a2": hook,
    "GET /kw": null, // the rule given by keyword
    "GET /b1": null, // "/b1" or "/b2", either branch: the hook lets the second through
    "GET /c1": hook, // "/c1" or "/c2", neither let through
    "GET /x9": null, // "/x9" and PREFIX, not "/x9", which the hook would refuse
    "GET /d1": null, // one branch not known
    "GET /kw2": hook,
  });
});

// Redash and CTFd install their hooks inside `def init_app(app)` and `def init_request_processors(app)`.
// Such a hook was read only when its receiver's name was assigned an app in the same file, which also
// credited a hook in a function nobody calls, on a parameter shadowing the module's `app`.
test("a hook installed on a parameter runs for what each call passes, and one never installed protects nothing", () => {
  const refuse = (name, on = "app") => `    @${on}.before_request\n    def ${name}():\n        if "user_id" not in session:\n            abort(401)\n`;
  const files = {
    "pkg/__init__.py": "",
    "pkg/app.py":
      "from flask import Flask\n\nfrom pkg import admin as admin_module\nfrom pkg import views\nfrom pkg.hooks import install\nfrom pkg.sec import security\n\n\n" +
      "def create_app():\n    app = Flask(__name__)\n    security.init_app(app)\n    install(admin_module.admin)\n    app.register_blueprint(views.bp)\n    app.register_blueprint(admin_module.admin)\n    return app\n\n\napp = create_app()\n",
    "pkg/sec/__init__.py": "",
    "pkg/sec/security.py":
      "from flask import abort, request, session\n\n\ndef init_app(app):\n    @app.before_request\n    def require_login():\n" +
      '        if request.path == "/public":\n            return\n        if "user_id" not in session:\n            abort(401)\n',
    "pkg/hooks.py":
      'from flask import abort, session\n\n\ndef require_admin():\n    if "admin" not in session:\n        abort(403)\n\n\ndef install(target):\n    target.before_request(require_admin)\n',
    "pkg/admin.py": 'from flask import Blueprint\n\nadmin = Blueprint("admin", __name__, url_prefix="/admin")\n\n\n@admin.get("/stats")\ndef stats():\n    return "stats"\n',
    "pkg/views.py":
      'from flask import Blueprint\n\nbp = Blueprint("views", __name__)\n\n\n@bp.get("/public")\ndef public():\n    return "public"\n\n\n@bp.get("/home")\ndef home():\n    return "home"\n',
    "other/__init__.py": "",
    "other/app.py":
      "from flask import Blueprint, Flask, abort, session\n\napp = Flask(__name__)\nHOOKS = []\n" +
      'one = Blueprint("one", __name__)\ntwo = Blueprint("two", __name__)\n\n\n' +
      'def check_member():\n    if "user_id" not in session:\n        abort(401)\n\n\ndef guard(target):\n    target.before_request(check_member)\n\n\n' +
      "class Registry:\n    def before_request(self, f):\n        self.f = f\n        return f\n\n\nregistry = Registry()\n" +
      "guard(one)\nguard(two)\nguard(registry)\n\n\n" +
      "def never_called(app):\n" + refuse("refuse") + "\n\ndef passed_around(app):\n" + refuse("refuse_too") + "\n\nHOOKS.append(passed_around)\n\n\n" +
      "def setup():\n    def nested(app):\n" + refuse("refuse_three").replace(/^/gm, "    ") + "\n    return nested\n\n\n" +
      '@app.get("/open")\ndef open_view():\n    return "open"\n\n\n' +
      '@one.get("/one")\ndef one_view():\n    return "one"\n\n\n@two.get("/two")\ndef two_view():\n    return "two"\n\n\n' +
      "app.register_blueprint(one)\napp.register_blueprint(two)\n",
    "third/__init__.py": "",
    "third/app.py": 'from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.get("/third")\ndef third():\n    return "third"\n\n\nimport third.hooks  # noqa: E402, F401\n',
    "third/hooks.py": "from flask import abort, session\n\nfrom third.app import app\n\n\n" + refuse("gate").replace(/^    /gm, ""),
    "fourth/__init__.py": "",
    "fourth/app.py":
      'from flask import Blueprint, Flask, abort, session\n\napp = Flask(__name__)\nside = Blueprint("side", __name__)\n\n\n' +
      "def watch(bp):\n" + refuse("everywhere", "bp").replace("before_request", "before_app_request") + "\n\nwatch(side)\napp.register_blueprint(side)\n\n\n" +
      '@app.get("/fourth")\ndef fourth():\n    return "fourth"\n',
  };
  const report = run(files, checkAuthentication);
  // Checked in Flask 3.1.3 with its test client and no session: /home, /admin/stats and /third refuse,
  // /public and /open answer 200; /one and /two, each a blueprint `guard` is called with, refuse, and
  // `guard(registry)` installs nothing on the app; /fourth refuses, by a blueprint's before_app_request.
  assert.deepEqual(verdicts(report), {
    "GET /home": `a before_request hook (pkg/sec/security.py:${lineOf(files["pkg/sec/security.py"], "@app.before_request")})`,
    "GET /public": null,
    "GET /stats": `a before_request hook (pkg/hooks.py:${lineOf(files["pkg/hooks.py"], "def require_admin")})`,
    "GET /open": null,
    "GET /one": `a before_request hook (other/app.py:${lineOf(files["other/app.py"], "def check_member")})`,
    "GET /two": `a before_request hook (other/app.py:${lineOf(files["other/app.py"], "def check_member")})`,
    "GET /third": `a before_request hook (third/hooks.py:${lineOf(files["third/hooks.py"], "@app.before_request")})`,
    "GET /fourth": `a before_request hook (fourth/app.py:${lineOf(files["fourth/app.py"], "@bp.before_app_request")})`,
  });
});

// `app = create_app()` in wsgi.py, and `admin = make_admin()`: a name assigned what a project function
// returns. Read by the call it is assigned alone, neither was known to be an app or a blueprint, so a
// hook on the app protected nothing and the factory's blueprint had no prefix.
test("an app or blueprint made by a factory is the one the factory returns", () => {
  const files = {
    "pkg/__init__.py":
      "from flask import Flask\n\nfrom pkg.admin import admin\nfrom pkg.apiv import api_bp\nfrom pkg.extra import either, extra, picked, picked2\nfrom pkg.views import bp\n\n\n" +
      'def create_app():\n    app = Flask(__name__)\n    app.register_blueprint(bp)\n    app.register_blueprint(admin, url_prefix="/admin")\n' +
      "    app.register_blueprint(extra)\n    app.register_blueprint(either)\n    app.register_blueprint(api_bp)\n" +
      "    app.register_blueprint(picked)\n    app.register_blueprint(picked2)\n    return app\n",
    "pkg/admin.py":
      'from flask import Blueprint, abort, session\n\n\ndef make_admin():\n    bp = Blueprint("admin", __name__)\n\n' +
      '    @bp.before_request\n    def admin_only():\n        if "admin" not in session:\n            abort(403)\n\n' +
      '    @bp.get("/stats")\n    def stats():\n        return "stats"\n\n' +
      '    @bp.get("/open")\n    def open_page():\n        return "open"\n\n    return bp\n\n\nadmin = make_admin()\n\n\n' +
      '@admin.get("/late")\ndef late():\n    return "late"\n\n\nstaff = admin\n\n\n@staff.get("/staff")\ndef staff_page():\n    return "staff"\n',
    "pkg/extra.py":
      'import os\n\nfrom flask import Blueprint\n\nFLAG = os.environ.get("NO_EXTRA") == "1"\n\n\n' +
      'def maybe():\n    if FLAG:\n        return None\n    made = Blueprint("extra", __name__, url_prefix="/x")\n    return made\n\n\n' +
      'def either():\n    if FLAG:\n        return getattr(os, "nothing")\n    made = Blueprint("either", __name__, url_prefix="/y")\n    return made\n\n\n' +
      'def pick():\n    if FLAG:\n        one = Blueprint("p1", __name__, url_prefix="/p1")\n        return one\n    two = Blueprint("p2", __name__, url_prefix="/p2")\n    return two\n\n\n' +
      'def pick2():\n    if FLAG:\n        three = Blueprint("q1", __name__, url_prefix="/q1")\n        return three\n' +
      '    four = Blueprint("q2", __name__, url_prefix=os.environ.get("PREFIX", "/q2"))\n    return four\n\n\n' +
      'extra = maybe()\neither = either()\npicked = pick()\npicked2 = pick2()\n\n\n@extra.get("/thing")\ndef thing():\n    return "thing"\n\n\n' +
      '@either.get("/other")\ndef other():\n    return "other"\n\n\n@picked.get("/z")\ndef z():\n    return "z"\n\n\n@picked2.get("/z2")\ndef z2():\n    return "z2"\n',
    "pkg/apiv.py":
      "from flask import Blueprint, abort, session\nfrom flask_restx import Api, Resource\n\n\n" +
      'def make_api_bp():\n    b = Blueprint("api", __name__, url_prefix="/api")\n\n    @b.before_request\n    def api_only():\n        if "user_id" not in session:\n            abort(403)\n\n    return b\n\n\n' +
      "api_bp = make_api_bp()\napi = Api(api_bp, doc=False)\n\n\n" +
      '@api.route("/items")\nclass Items(Resource):\n    def get(self):\n        return []\n',
    "pkg/views.py": 'from flask import Blueprint\n\nbp = Blueprint("views", __name__)\n\n\n@bp.get("/home")\ndef home():\n    return "home"\n',
    "wsgi.py": 'from pkg import create_app\n\napp = create_app()\n\n\n@app.get("/direct")\ndef direct():\n    return "direct"\n\n\nimport hooks  # noqa: E402, F401\n',
    "cli.py": 'from pkg import create_app\n\nother = create_app()\n\n\n@other.get("/o")\ndef o():\n    return "o"\n',
    "hooks.py":
      "from flask import abort, request, session\n\nfrom wsgi import app\n\n\n@app.before_request\ndef require_login():\n" +
      '    if request.path in ("/elsewhere", "/admin/open", "/admin/late", "/admin/staff", "/api/items", "/p2/z"):\n        return\n    if "user_id" not in session:\n        abort(401)\n',
  };
  const report = run(files, checkAuthentication);
  const hook = `a before_request hook (hooks.py:${lineOf(files["hooks.py"], "@app.before_request")})`;
  const admin = `a before_request hook (pkg/admin.py:${lineOf(files["pkg/admin.py"], "@bp.before_request")})`;
  const api = `a before_request hook (pkg/apiv.py:${lineOf(files["pkg/apiv.py"], "@b.before_request")})`;
  // Checked in Flask 3.1.3 with its test client and no session: /p2/z answers 200, /admin/open,
  // /admin/late, /admin/staff and /api/items 403, and every other route 401 -- /y/other and /q2/z2 included, which
  // are left open here because `either` has a return not traced and pick2() a prefix not written out.
  assert.deepEqual(verdicts(report), {
    "GET /direct": hook, // on the app itself, outside the package the app is made in
    "GET /o": null, // on another app create_app() makes, in cli.py, which the hook is not on
    "GET /home": hook,
    "GET /stats": hook, // "/admin/stats", the prefix given to what make_admin() returns
    "GET /open": admin, // "/admin/open", let through by the app's hook
    "GET /late": admin, // on `admin`, the blueprint the hook inside make_admin() is on
    "GET /staff": admin, // on `staff = admin`
    "GET /thing": hook, // "/x/thing"; maybe() may return None, which is no blueprint
    "GET /other": null,
    "GET /z": null, // "/p1/z" or "/p2/z": either blueprint pick() returns
    "GET /z2": null,
    "ROUTE /items": api, // "/api/items", on an Api mounted on what make_api_bp() returns
  });
});

// `return Blueprint(...)` and `return Flask(...)` were not followed, so what such a factory made was
// unknown. And two calls of one factory make two blueprints: read as one, a hook put on `b1` was
// credited on `b2`'s routes, which Flask serves to anyone.
test("a factory returning the app or blueprint it makes is followed, and each call of it makes its own", () => {
  const app =
    "from flask import Blueprint, Flask, abort, request, session\n\n\ndef create_app():\n    return Flask(__name__)\n\n\n" +
    'def make_b(name):\n    bp = Blueprint(name, __name__)\n    return bp\n\n\ndef make_c():\n    return Blueprint("c", __name__, url_prefix="/c")\n\n\n' +
    'def make_e():\n    e = Blueprint("e", __name__)\n\n    @e.get("/w")\n    def w():\n        return "w"\n\n    return e\n\n\n' +
    'def make_g(name):\n    g = Blueprint(name, __name__)\n\n    @g.get("/v")\n    def v():\n        return "v"\n\n    return g\n\n\n' +
    'def make_k():\n    k = Blueprint("k", __name__)\n\n    @k.get("/u")\n    def u():\n        return "u"\n\n    return k\n\n\n' +
    'def setup():\n    made = make_k()\n    return made\n\n\n' +
    'def make_t():\n    return Blueprint("t", __name__, url_prefix="/t") if ON else Blueprint("t", __name__, url_prefix="/t2")\n\n\n' +
    'def make_t3():\n    return Blueprint("t3", __name__, url_prefix="/u1") if ON else Blueprint("t3", __name__, url_prefix="/u2")\n\n\n' +
    'def make_q():\n    return Blueprint("q", __name__, url_prefix="/q", template_folder="one if two else three")\n\n\n' +
    "def choose(bp):\n    return bp\n\n\n" +
    'def refuse():\n    if "user_id" not in session:\n        abort(401)\n\n\n' +
    'def make_h(name):\n    h = Blueprint(name, __name__)\n    h.before_request(refuse)\n\n    @h.get("/hh")\n    def hh():\n        return "hh"\n\n    return h\n\n\n' +
    'ON = False\napp = create_app()\nb1 = make_b("one")\nb2 = make_b("two")\nb1.before_request(refuse)\nc = make_c()\n\n\n' +
    '@app.before_request\ndef gate():\n    if request.path in ("/one/x", "/two/y", "/z", "/g1/v", "/g2/v", "/k1/u", "/k2/u", "/h1/hh", "/h2/hh", "/h1/mine", "/t2/s", "/pl", "/pb/ch", "/pc/c2"):\n        return\n    if "user_id" not in session:\n        abort(401)\n\n\n' +
    '@app.get("/direct")\ndef direct():\n    return "direct"\n\n\n@b1.get("/x")\ndef x():\n    return "x"\n\n\n' +
    '@b2.get("/y")\ndef y():\n    return "y"\n\n\n@c.get("/z")\ndef z():\n    return "z"\n\n\n' +
    'app.register_blueprint(b1, url_prefix="/one")\napp.register_blueprint(b2, url_prefix="/two")\n' +
    'app.register_blueprint(c)\napp.register_blueprint(c, name="c2", url_prefix="/c2")\napp.register_blueprint(make_e(), url_prefix="/e")\n' +
    'made = []\nfor n in ("g1", "g2"):\n    last = make_g(n)\n    made.append(last)\nlast.before_request(refuse)\n' +
    'for each in made:\n    app.register_blueprint(each, url_prefix="/" + each.name)\n' +
    'first = setup()\nsecond = setup()\nfirst.before_request(refuse)\n' +
    'h1 = make_h("h1")\nh2 = make_h("h2")\nt = make_t()\nt3 = make_t3()\n' +
    'pa = Blueprint("pa", __name__, url_prefix="/pa")\npb = Blueprint("pb", __name__, url_prefix="/pb")\nchosen = pa if ON else pb\n' +
    'pc = Blueprint("pc", __name__, url_prefix="/pc")\npd = Blueprint("pd", __name__, url_prefix="/pd")\nchosen2 = pc if ON else pd\n' +
    'pe = Blueprint("pe", __name__, url_prefix="/pe")\npf = Blueprint("pf", __name__, url_prefix="/pf")\nchosen3 = choose(pe if ON else pf)\nq = make_q()\nplain = Blueprint("plain", __name__)\nalias = plain\nalias.before_request(refuse)\n\n\n' +
    '@t.get("/s")\ndef s():\n    return "s"\n\n\n@t3.get("/s2")\ndef s2():\n    return "s2"\n\n\n@chosen.get("/ch")\ndef ch():\n    return "ch"\n\n\n@chosen2.get("/c2")\ndef c2():\n    return "c2"\n\n\n@chosen3.get("/c3")\ndef c3():\n    return "c3"\n\n\n@q.get("/qq")\ndef qq():\n    return "qq"\n\n\n@plain.get("/pl")\ndef pl():\n    return "pl"\n\n\n@h1.get("/mine")\ndef mine():\n    return "mine"\n\n\n' +
    'app.register_blueprint(h1, url_prefix="/h1")\napp.register_blueprint(h2, url_prefix="/h2")\napp.register_blueprint(t)\napp.register_blueprint(plain)\n' +
    "app.register_blueprint(t3)\napp.register_blueprint(chosen)\napp.register_blueprint(chosen2)\napp.register_blueprint(chosen3)\napp.register_blueprint(q)\n" +
    'app.register_blueprint(first, url_prefix="/k1", name="k1")\napp.register_blueprint(second, url_prefix="/k2", name="k2")\n';
  const report = run({ "app.py": app }, checkAuthentication);
  const gate = `a before_request hook (app.py:${lineOf(app, "@app.before_request")})`;
  const refuse = `a before_request hook (app.py:${lineOf(app, "def refuse")})`;
  // Checked in Flask 3.1.3 with its test client and no session: /two/y, /g1/v, /k2/u, /t2/s and /pb/ch answer 200,
  // the app's hook letting them through and `refuse` not on their blueprints; every other route refuses.
  assert.deepEqual(verdicts(report), {
    "GET /direct": gate, // on the app create_app() returns
    "GET /x": refuse, // "/one/x", let through by the app's hook
    "GET /y": null, // b2 is not b1
    "GET /z": gate, // "/c/z" and "/c2/z", the prefix make_c()'s Blueprint gives, and not "/z"
    "GET /w": gate, // "/e/w", registered as make_e() returns it
    "GET /v": null, // made in a loop: the hook is on the last one only
    "GET /u": null, // make_k() runs once per call of setup(), which runs twice
    "GET /hh": refuse, // put on the blueprint inside make_h(), so on both it makes
    "GET /mine": refuse, // on h1, which make_h() put the hook on
    "GET /s": null, // "/t/s" or "/t2/s", either branch: the hook lets the second through
    "GET /s2": gate, // "/u1/s2" or "/u2/s2", neither let through
    "GET /ch": null, // on pa or pb: "/pb/ch" is let through
    "GET /c2": null, // on pc or pd: "/pc/c2" is let through; Flask, with ON false, serves "/pd/c2" and refuses it
    "GET /c3": gate, // "/pe/c3" or "/pf/c3", through choose()
    "GET /qq": gate, // "/q/qq": the `if` and `else` in a string are not a conditional
    "GET /pl": refuse, // put on `alias`, which is `plain`
  });
});

test("a path rule reaches a route whose variables can take the path it names, and a rule whose values are not written out reaches every route", () => {
  const head = "from flask import Flask, abort, request, session\n\napp = Flask(__name__)\n";
  const get = (p) => `\n\n@app.get("${p}")\ndef v${p.replace(/\W/g, "")}():\n    return ""\n`;
  const one =
    head + "\n\n@app.before_request\ndef require_login():\n" +
    '    if request.path == "/docs/intro" or request.path == "/users/5" or request.path == "/files/a/b" or request.path.startswith("/public"):\n        return\n' +
    LOGIN + get("/docs/<page>") + get("/users/<int:id>/posts") + get("/<lang>/home") + get("/files/<path:name>") + get("/reports/<int:id>");
  const two = head + 'PUBLIC = {"/about"}\n\n\n@app.before_request\ndef require_login():\n    if request.path in PUBLIC:\n        return\n' + LOGIN + get("/accounts");
  const three = head + 'OPEN = ("site.about",)\n\n\n@app.before_request\ndef require_login():\n    if request.endpoint in OPEN:\n        return\n' + LOGIN + get("/billing");
  const report = run({ "one/app.py": one, "two/app.py": two, "three/app.py": three }, checkAuthentication);
  const hook = `a before_request hook (one/app.py:${lineOf(one, "@app.before_request")})`;
  assert.deepEqual(verdicts(report), {
    "GET /docs/<page>": null, // "/docs/intro"
    "GET /users/<int:id>/posts": hook, // "/users/5" is not a whole path of this rule
    "GET /<lang>/home": null, // `lang` may be "public"
    "GET /files/<path:name>": null, // a `path` variable takes "a/b"
    "GET /reports/<int:id>": hook,
    "GET /accounts": null,
    "GET /billing": null,
  });
});

test("a flask-restx route's full path: the blueprint's prefix, the Api's, then the namespace's path", () => {
  const init =
    "from flask import Blueprint, Flask, abort, request\nfrom flask_login import current_user\nfrom flask_restx import Api, Resource\n\n" +
    "from .users import ns as users\nfrom .teams import ns as teams\nfrom .things import ns as things\n\n" +
    'app = Flask(__name__)\nbp = Blueprint("api", __name__, url_prefix="/api")\napi = Api(bp, prefix="/v2", doc=False)\n' +
    'api.add_namespace(users, "/people")\napi.add_namespace(teams)\napi.add_namespace(things)\nopen_ns = api.namespace("public")\napp.register_blueprint(bp)\n\n\n' +
    "@app.before_request\ndef require_login():\n" +
    '    if request.path.startswith("/api/v2/users") or request.path.startswith("/api/v2/squads") or request.path.startswith("/api/v2/public/"):\n        return\n' +
    REFUSE + '\n\n@open_ns.route("/docs")\nclass Docs(Resource):\n    def get(self):\n        return {}\n';
  const resource = (ns) => `from flask_restx import Namespace, Resource\n\nns = ${ns}\n\n\n@ns.route("/<int:id>")\nclass R(Resource):\n    def delete(self, id):\n        return {}\n`;
  const report = run(
    {
      "api/__init__.py": init,
      "api/users.py": resource('Namespace("users")'), // at "/people", the path add_namespace gives
      "api/teams.py": resource('Namespace("teams", path="/squads")'),
      "api/things.py": resource('Namespace("things")'),
    },
    checkAuthentication
  );
  const hook = `a before_request hook (api/__init__.py:${lineOf(init, "@app.before_request")})`;
  assert.deepEqual(byFile(report), {
    "api/__init__.py": null, // "/api/v2/public/docs"
    "api/users.py": hook, // "/api/v2/people/<int:id>": not under its name, "/api/v2/users"
    "api/teams.py": null, // "/api/v2/squads/<int:id>"
    "api/things.py": hook, // "/api/v2/things/<int:id>"
  });
});

test("a namespace added to two Apis is protected only when both are", () => {
  const app = (hooks) =>
    "from flask import Blueprint, Flask, abort\nfrom flask_login import current_user\nfrom flask_restx import Api, Namespace, Resource\n\n" +
    'app = Flask(__name__)\none = Blueprint("one", __name__, url_prefix="/one")\ntwo = Blueprint("two", __name__, url_prefix="/two")\n' +
    'ns = Namespace("things")\nfor_one = Api(one)\nfor_two = Api(two)\nfor_one.add_namespace(ns)\nfor_two.add_namespace(ns)\n' +
    "app.register_blueprint(one)\napp.register_blueprint(two)\n" +
    hooks.map((bp) => `\n\n@${bp}.before_request\ndef require_login_${bp}():\n` + REFUSE).join("") +
    '\n\n@ns.route("/x")\nclass X(Resource):\n    def post(self):\n        return {}\n';
  const both = app(["one", "two"]);
  const report = run({ "a/app.py": app(["one"]), "b/app.py": both }, checkAuthentication);
  assert.deepEqual(byFile(report), {
    "a/app.py": null, // served at "/two/things/x" without a hook
    "b/app.py": `a before_request hook (b/app.py:${lineOf(both, "@one.before_request")})`,
  });
});

test("an import followed by a comment is read: a library decorator, and a blueprint from another module", () => {
  const views =
    "from flask import Blueprint\nfrom flask_login import login_required  # noqa: F401\n\n" +
    'bp = Blueprint("views", __name__)\n\n\n@bp.get("/inbox")\n@login_required\ndef inbox():\n    return ""\n';
  const hooks =
    "from flask import Blueprint, abort\nfrom flask_login import current_user\n\n" +
    'admin = Blueprint("admin", __name__)\n\n\n@admin.before_request\ndef require_login():\n' + REFUSE;
  const routes = 'from .hooks import admin  # noqa: E402\n\n\n@admin.get("/stats")\ndef stats():\n    return ""\n';
  const report = run({ "app/views.py": views, "app/hooks.py": hooks, "app/routes.py": routes }, checkAuthentication);
  assert.deepEqual(verdicts(report), {
    "GET /inbox": "@login_required from flask_login",
    "GET /stats": `a before_request hook (app/hooks.py:${lineOf(hooks, "@admin.before_request")})`,
  });
});
