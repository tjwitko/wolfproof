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
      // The prefix is not part of the path read here, so "/stats" may well be "/public/stats".
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
      // A namespace's path is not read, so the full path of the route is not known.
      "bypath.py":
        head + 'bp = Blueprint("c", __name__)\napi = Api(bp)\nns = Namespace("c")\napi.add_namespace(ns)\n\n\n@bp.before_request\ndef require_login():\n' +
        '    if request.path.startswith("/c/public"):\n        return\n' + REFUSE + route("ns", "/bypath"),
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
