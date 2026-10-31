// Fastify hooks scoped by directory: @fastify/autoload's `autohooks` files (agent/authentication-fastify.mjs).
// Each expected verdict is what Fastify 5.12.7 with @fastify/autoload 6.5.1 did with the same files:
// an anonymous request either reached the route's handler (open) or was refused before it (protected).
// Two cases are refused by Fastify and still open here, on purpose, and say so.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { checkAuthentication } from "./authentication.mjs";

/** Each route's verdict, keyed `METHOD file route`: what protects it, or null. */
function verdicts(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "fastify-"));
  try {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), text);
    }
    const r = checkAuthentication(dir);
    return {
      routes: Object.fromEntries(r.routes.map((x) => [`${x.method} ${x.file} ${x.route}`, x.protectedBy || null])),
      exempt: r.exempt.map((x) => `${x.method} ${x.file} ${x.route}`),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// fastify/demo's hook, as written in src/routes/api/autohooks.ts.
const DEMO_HOOK = `import { FastifyInstance } from 'fastify'

export default async function (fastify: FastifyInstance) {
  fastify.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/api/auth/login')) {
      return
    }

    if (!request.session.user) {
      reply.unauthorized('You must be authenticated to access this route.')
    }
  })
}
`;
// The same refusal, with `pass` as an early return ahead of it.
const hook = (pass) => `export default async function (fastify) {
  fastify.addHook('onRequest', async (request, reply) => {${pass ? `\n    if (${pass}) {\n      return\n    }` : ""}
    if (!request.session?.user) {
      reply.unauthorized('You must be authenticated.')
    }
  })
}
`;
const route = (method, p) => `export default async function (fastify) {
  fastify.${method}('${p}', async () => ({ ok: true }))
}
`;
const app = (options) => `import path from 'node:path'
import fastifyAutoload from '@fastify/autoload'

export default async function serviceApp (fastify, opts) {
  fastify.register(fastifyAutoload, {
    dir: path.join(import.meta.dirname, 'routes'),
    ${options}
  })
}
`;
// fastify/demo registers its app once, with no options, so a spread of them carries no prefix.
const SERVER = `import Fastify from 'fastify'
import fp from 'fastify-plugin'
import serviceApp from './app.js'

const app = Fastify()
app.register(fp(serviceApp))
`;
const project = (options, routes, extra = {}) => ({
  "src/app.ts": app(options),
  "src/server.ts": SERVER,
  ...Object.fromEntries(Object.entries(routes).map(([k, v]) => [`src/routes/${k}`, v])),
  ...extra,
});
const BY_HOOK = (file, line = 2) => `an autohooks onRequest hook (src/routes/${file}:${line})`;

test("fastify/demo: the API's autohooks protects every route under it, and not the one outside", () => {
  const { routes, exempt } = verdicts(
    project("autoHooks: true,\n    cascadeHooks: true,\n    options: { ...opts }", {
      "api/autohooks.ts": DEMO_HOOK,
      "api/index.ts": route("get", "/"),
      "api/users/index.ts": route("put", "/update-password"),
      "api/tasks/index.ts": route("delete", "/:id"),
      "api/auth/index.ts": route("post", "/login"),
      "api/auth/session/index.ts": route("get", "/"),
      "home.ts": route("get", "/home"),
    })
  );
  const demo = "an autohooks onRequest hook (src/routes/api/autohooks.ts:4)";
  assert.equal(routes["GET src/routes/api/index.ts /"], demo);
  assert.equal(routes["PUT src/routes/api/users/index.ts /update-password"], demo);
  assert.equal(routes["DELETE src/routes/api/tasks/index.ts /:id"], demo);
  // /api/auth/session does not start with /api/auth/login, so the hook's pass-through misses it.
  assert.equal(routes["GET src/routes/api/auth/session/index.ts /"], demo);
  assert.equal(routes["GET src/routes/home.ts /home"], null, "outside the hook's directory");
  assert.deepEqual(exempt, ["POST src/routes/api/auth/index.ts /login"]);
});

test("without cascadeHooks a hook reaches its own directory only", () => {
  const { routes } = verdicts(project("autoHooks: true", { "api/autohooks.mjs": hook(), "api/index.mjs": route("get", "/"), "api/users/index.mjs": route("get", "/me") }));
  assert.equal(routes["GET src/routes/api/index.mjs /"], BY_HOOK("api/autohooks.mjs"));
  assert.equal(routes["GET src/routes/api/users/index.mjs /me"], null);
});

test("without autoHooks the file is not loaded, and protects nothing", () => {
  const { routes } = verdicts(project("cascadeHooks: true", { "api/autohooks.mjs": hook(), "api/index.mjs": route("get", "/") }));
  assert.equal(routes["GET src/routes/api/index.mjs /"], null);
});

test("a hook does not reach a sibling directory, and the project-wide hook rule no longer reads it", () => {
  // `fastify.authenticate` names authentication within the project-wide rule's reach; read as
  // app-wide, it credited the public route.
  const named = "export default async function (fastify) {\n  fastify.addHook('onRequest', fastify.authenticate)\n}\n";
  const { routes } = verdicts(project("autoHooks: true, cascadeHooks: true", { "admin/autohooks.mjs": named, "admin/index.mjs": route("get", "/"), "public/index.mjs": route("get", "/") }));
  assert.equal(routes["GET src/routes/admin/index.mjs /"], BY_HOOK("admin/autohooks.mjs"));
  assert.equal(routes["GET src/routes/public/index.mjs /"], null);
});

test("overwriteHooks: a directory with its own file drops its parent's hooks", () => {
  const { routes } = verdicts(
    project("autoHooks: true, cascadeHooks: true, overwriteHooks: true", {
      "api/autohooks.mjs": hook(),
      "api/index.mjs": route("get", "/"),
      "api/open/autohooks.mjs": "export default async function (f) {\n  f.addHook('onRequest', async () => {})\n}\n",
      "api/open/index.mjs": route("get", "/x"),
      "api/deep/index.mjs": route("get", "/y"),
    })
  );
  assert.equal(routes["GET src/routes/api/index.mjs /"], BY_HOOK("api/autohooks.mjs"));
  assert.equal(routes["GET src/routes/api/deep/index.mjs /y"], BY_HOOK("api/autohooks.mjs"));
  assert.equal(routes["GET src/routes/api/open/index.mjs /x"], null);
});

test("a path pass-through is matched against the URL: the prefix, the directories and the route", () => {
  const { routes } = verdicts(
    project("autoHooks: true, cascadeHooks: true, options: { prefix: '/v1' }", {
      "api/autohooks.mjs": hook("request.url.startsWith('/v1/api/public')"),
      "api/public/index.mjs": route("get", "/"),
      "api/private/index.mjs": route("get", "/"),
    })
  );
  assert.equal(routes["GET src/routes/api/public/index.mjs /"], null);
  assert.equal(routes["GET src/routes/api/private/index.mjs /"], BY_HOOK("api/autohooks.mjs"));
});

test("dirNameRoutePrefix false leaves the directories out of the URL", () => {
  const { routes } = verdicts(
    project("autoHooks: true, cascadeHooks: true, dirNameRoutePrefix: false", {
      "api/autohooks.mjs": hook("request.url.startsWith('/public')"),
      "api/public/index.mjs": route("get", "/public"),
      "api/private/index.mjs": route("get", "/private"),
    })
  );
  assert.equal(routes["GET src/routes/api/public/index.mjs /public"], null);
  assert.equal(routes["GET src/routes/api/private/index.mjs /private"], BY_HOOK("api/autohooks.mjs"));
});

test("a negated rule, a list of paths, and a parameter that can be the passed path", () => {
  const negated = verdicts(
    project("autoHooks: true, cascadeHooks: true", {
      "api/autohooks.mjs": hook("!request.url.startsWith('/api/private')"),
      "api/private/index.mjs": route("get", "/"),
      "api/other/index.mjs": route("get", "/"),
    })
  ).routes;
  assert.equal(negated["GET src/routes/api/private/index.mjs /"], BY_HOOK("api/autohooks.mjs"));
  assert.equal(negated["GET src/routes/api/other/index.mjs /"], null);

  const listed = verdicts(
    project("autoHooks: true, cascadeHooks: true", {
      "api/autohooks.mjs": hook("['/api/a', '/api/b/:id'].includes(request.routeOptions.url)"),
      "api/a/index.mjs": route("get", "/"),
      "api/b/index.mjs": route("get", "/:id"),
      "api/c/index.mjs": route("get", "/"),
    })
  ).routes;
  assert.equal(listed["GET src/routes/api/a/index.mjs /"], null);
  assert.equal(listed["GET src/routes/api/b/index.mjs /:id"], null);
  assert.equal(listed["GET src/routes/api/c/index.mjs /"], BY_HOOK("api/autohooks.mjs"));

  // GET /api/docs reaches `/:page`, and the hook lets it through.
  const param = verdicts(project("autoHooks: true, cascadeHooks: true", { "api/autohooks.mjs": hook("request.url.startsWith('/api/docs')"), "api/index.mjs": route("get", "/:page") })).routes;
  assert.equal(param["GET src/routes/api/index.mjs /:page"], null);
});

// Fastify refused both of these, and the check leaves them open: what the pass-through lets through
// cannot be bounded when the prefix is not written out, or the condition is not a path rule.
test("an unwritten prefix, or a pass-through not on the path, leaves the routes open", () => {
  const prefix = verdicts(project("autoHooks: true, cascadeHooks: true, options: { prefix: process.env.P || '' }", { "api/autohooks.mjs": hook("request.url.startsWith('/api/public')"), "api/private/index.mjs": route("get", "/") })).routes;
  assert.equal(prefix["GET src/routes/api/private/index.mjs /"], null);
  const method = verdicts(project("autoHooks: true, cascadeHooks: true", { "api/autohooks.mjs": hook("request.method === 'OPTIONS'"), "api/index.mjs": route("get", "/") })).routes;
  assert.equal(method["GET src/routes/api/index.mjs /"], null);
});

test("a spread of the app's options carries no prefix only when every registration of the app is read", () => {
  const files = (server) =>
    project("autoHooks: true, cascadeHooks: true, options: { ...opts }", { "api/autohooks.mjs": hook("request.url.startsWith('/api/public')"), "api/private/index.mjs": route("get", "/") }, { "src/server.ts": server });
  const key = "GET src/routes/api/private/index.mjs /";
  assert.equal(verdicts(files(SERVER)).routes[key], BY_HOOK("api/autohooks.mjs"));
  assert.equal(verdicts(files(SERVER.replace("fp(serviceApp))", "fp(serviceApp), { prefix: '/v2' })"))).routes[key], null, "registered with options");
  assert.equal(verdicts(files("export const nothing = 1\n")).routes[key], null, "started by fastify-cli: no registration here");
  // fastify/demo's test helper registers the app with the test configuration; a test is not how it is served.
  const withTest = { ...files(SERVER), "test/helper.ts": "import fp from 'fastify-plugin'\nimport serviceApp from '../src/app.js'\nexport function build (app) { app.register(fp(serviceApp), config()) }\n" };
  assert.equal(verdicts(withTest).routes[key], BY_HOOK("api/autohooks.mjs"));
});

test("hooks that run after the handler, or only log, protect nothing", () => {
  const after = "export default async function (f) {\n  f.addHook('onResponse', async (request, reply) => {\n    if (!request.session?.user) {\n      return reply.code(401).send()\n    }\n  })\n}\n";
  const logs = "export default async function (f) {\n  f.addHook('onRequest', async (request, reply) => {\n    if (!request.session?.user) {\n      request.log.info('anonymous')\n    }\n  })\n}\n";
  // Sending a reply ends the request, but one that answers 200 refuses nobody.
  const ok = logs.replace("request.log.info('anonymous')", "reply.code(200).send({ welcome: true })");
  for (const h of [after, logs, ok]) {
    assert.equal(verdicts(project("autoHooks: true, cascadeHooks: true", { "api/autohooks.mjs": h, "api/index.mjs": route("get", "/") })).routes["GET src/routes/api/index.mjs /"], null, h);
  }
});

test("a hook function declared in the file, a callback hook, and CommonJS", () => {
  // Named for nothing about authentication, so it is credited for its body, not its name.
  const named = "async function membersOnly (request, reply) {\n  if (!request.session?.user) {\n    return reply.code(401).send({ message: 'no' })\n  }\n}\nexport default async function (f) {\n  f.addHook('preHandler', membersOnly)\n}\n";
  const notRefusing = named.replace("reply.code(401)", "reply.code(200)");
  assert.equal(
    verdicts(project("autoHooks: true, cascadeHooks: true", { "api/autohooks.mjs": notRefusing, "api/index.mjs": route("get", "/") })).routes["GET src/routes/api/index.mjs /"],
    null,
    "a declared hook that answers 200"
  );
  assert.equal(
    verdicts(project("autoHooks: true, cascadeHooks: true", { "api/autohooks.mjs": named, "api/index.mjs": route("get", "/") })).routes["GET src/routes/api/index.mjs /"],
    "an autohooks preHandler hook (src/routes/api/autohooks.mjs:7)"
  );
  const callback = "export default async function (f) {\n  f.addHook('preValidation', (request, reply, done) => {\n    if (!request.session?.user) {\n      reply.code(403).send()\n      return\n    }\n    done()\n  })\n}\n";
  assert.equal(
    verdicts(project("autoHooks: true, cascadeHooks: true", { "api/autohooks.mjs": callback, "api/index.mjs": route("post", "/") })).routes["POST src/routes/api/index.mjs /"],
    "an autohooks preValidation hook (src/routes/api/autohooks.mjs:2)"
  );
  const cjs = {
    "app.js": "const path = require('node:path')\nconst AutoLoad = require('@fastify/autoload')\nmodule.exports = async function (fastify, opts) {\n  fastify.register(AutoLoad, {\n    dir: path.join(__dirname, 'routes'),\n    autoHooks: true,\n    cascadeHooks: true\n  })\n}\n",
    "routes/api/autohooks.js": "module.exports = async function (fastify) {\n  fastify.addHook('onRequest', async (request, reply) => {\n    if (!request.session?.user) {\n      reply.unauthorized()\n    }\n  })\n}\n",
    "routes/api/index.js": "module.exports = async function (fastify) {\n  fastify.get('/', async () => ({ ok: true }))\n}\n",
  };
  assert.equal(verdicts(cjs).routes["GET routes/api/index.js /"], "an autohooks onRequest hook (routes/api/autohooks.js:2)");
});
