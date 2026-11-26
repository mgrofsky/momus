import json, os, sqlite3, struct, sys, tempfile, unittest, urllib.parse
sys.path.insert(0, os.path.dirname(__file__))
import triage as T

# ---- invented nuclei requests and responses (the shape of finding_observations.raw_json). Each one is written
# from what the triage code reacts to and nothing else; hosts are reserved names, the ECR account is the AWS
# documentation account, and the .npmrc and every token below are made up.
def req(path, host, ua="Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"):
    return f"GET {path} HTTP/1.1\nHost: {host}\nUser-Agent: {ua}\nAccept: */*\n\n"

def rec(status_line, body, *headers):
    return "HTTP/1.1 " + status_line + "\n" + "".join(h + "\n" for h in headers) + "\n" + body

# Dockerfile: an ECR base image (account noted), COPY of .npmrc and package*.json, a RUN of a .sh script,
# a RUN mv of a PHP file, a RUN continued over two lines whose cp target is not a file name, and a final stage
# that copies the builder directory into the web root
DOCKER_REQUEST = req("/Dockerfile", "app1.alpha.example")
DOCKER_RESPONSE = rec("200 OK", (
    "FROM 111122223333.dkr.ecr.us-east-1.amazonaws.com/node-build:20 AS builder\n"
    "WORKDIR /build\n"
    "COPY .npmrc package*.json ./\n"
    "RUN npm ci && \\\n"
    "    cp -r assets \"$OUT_DIR\"\n"
    "COPY . .\n"
    "RUN ./build.sh\n"
    "\n"
    "FROM 111122223333.dkr.ecr.us-east-1.amazonaws.com/web-base:3\n"
    "WORKDIR /srv/www\n"
    "COPY --from=builder /build .\n"
    "RUN mv settings.dist.php settings.php\n"), "Content-Type: text/plain")
# docker-compose.yml: an image, a host credential file mounted into the container, an env_file list
COMPOSE_REQUEST = req("/docker-compose.yml", "app2.alpha.example")
COMPOSE_RESPONSE = rec("200 OK", (
    "services:\n"
    "  web:\n"
    "    image: web:dev\n"
    "    ports:\n"
    "      - \"8080:80\"\n"
    "    volumes:\n"
    "      - ./src:/var/www/html\n"
    "      - ~/.aws/credentials:/root/.aws/credentials:ro\n"
    "    env_file:\n"
    "      - config/.env\n"), "Content-Type: text/plain")
# .git/config: a remote without credentials
GITCFG_REQUEST = req("/.git/config", "app4.alpha.example")
GITCFG_RESPONSE = rec("200 OK", (
    "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
    "[remote \"origin\"]\n\turl = https://git.alpha.example/web/app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"), "Content-Type: text/plain")
# a .claude/ path answered by a wiki's HTML login page instead of the file
CLAUDE_REQUEST = req("/.claude/agents/index.md", "wiki.alpha.example")
CLAUDE_RESPONSE = rec("200 OK", (
    "<!DOCTYPE html>\n<html><head><title>Wiki - agents/index.md</title></head>\n<body>\n<h1>Login</h1>\n"
    "<form method=\"post\" action=\"/login\">\n"
    "<input type=\"text\" name=\"user\"> <input type=\"password\" name=\"pass\"> <button type=\"submit\">Log in</button></form>\n"
    "</body></html>\n"), "Content-Type: text/html; charset=utf-8")
# Prometheus text format: two *_version_info series and a few plain ones, no secrets in labels
METRICS_REQUEST = req("/metrics", "app9.alpha.example")
METRICS_RESPONSE = rec("200 OK", (
    "# HELP demoapp_version_info Application version.\n# TYPE demoapp_version_info gauge\n"
    "demoapp_version_info{version=\"v3.1.4\",major=\"3\",minor=\"1\",patch=\"4\"} 1\n"
    "# HELP demoapp_nodejs_version_info Node.js version.\n# TYPE demoapp_nodejs_version_info gauge\n"
    "demoapp_nodejs_version_info{version=\"v20.11.1\"} 1\n"
    "# TYPE demoapp_http_requests_total counter\n"
    "demoapp_http_requests_total{method=\"GET\",code=\"200\"} 4810\n"
    "demoapp_process_open_fds 57\n"), "Content-Type: text/plain; version=0.0.4")
# xss-fuzz on a login page: parameter u written back unescaped into an attribute, next to a password field
XSS_REQUEST = req("/?u=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-u%27%29%3E", "web1.alpha.example")
XSS_RESPONSE = rec("200 OK", (
    "<!DOCTYPE html>\n<html><head><title>Sign in</title></head>\n<body>\n"
    "<form method=\"post\" action=\"/login.php\">\n"
    "<label>Email <input type=\"email\" name=\"username\" value=\"'>\"<svg/onload=confirm('xss-u')>\"></label>\n"
    "<label>Password <input type=\"password\" name=\"password\"></label>\n"
    "<button type=\"submit\">Sign in</button>\n</form>\n</body></html>\n"), "Content-Type: text/html; charset=UTF-8")

def apache_index(path, *entries):
    """An Apache mod_autoindex page: sort links, a Parent Directory link, then one row per entry."""
    rows = "".join(f'<img src="/icons/{"folder" if e.endswith("/") else "unknown"}.gif" alt="[   ]"> <a href="{e}">{e}</a>  01-Jan-2030 00:00  -\n'
                   for e in entries)
    return (f"<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1>\n"
            f'<pre><a href="?C=N;O=D">Name</a> <a href="?C=M;O=A">Last modified</a><hr><a href="/">Parent Directory</a>\n{rows}<hr></pre></body></html>\n')

# /config/ listing with two files; config.php.dist ranks before config.php
CONFLIST_REQUEST = req("/config/", "app6.alpha.example")
CONFLIST_RESPONSE = rec("200 OK", apache_index("/config", "config.php", "config.php.dist"), "Content-Type: text/html")
# /log/ listing on a strict-SLA host: two files and two directories, one of which (config/) is worth one level down
LOGLIST_REQUEST = req("/log/", "app7.alpha.example")
LOGLIST_RESPONSE = rec("200 OK", apache_index("/log", "index.php", "config/", "tmp/", "upload.php"), "Content-Type: text/html")
# a CircleCI config: one orb reference, no secrets, no scripts
CIRCLECI_REQUEST = req("/.circleci/config.yml", "app3.alpha.example")
CIRCLECI_RESPONSE = rec("200 OK", (
    "version: 2.1\n"
    "orbs:\n"
    "  deploy: example/deploy-orb@1.2.0\n"
    "jobs:\n"
    "  build:\n"
    "    docker:\n"
    "      - image: cimg/node:20.11\n"
    "    steps:\n"
    "      - checkout\n"
    "      - run: npm ci && npm run build\n"
    "workflows:\n"
    "  main:\n"
    "    jobs:\n"
    "      - build\n"
    "      - deploy/release:\n"
    "          requires: [build]\n"), "Content-Type: text/plain")
# a long invented CircleCI config with nothing secret in it: several jobs, pipeline parameters, contexts, an approval
# step, parameter-store paths (names only, read at run time), cache keys and long hashes (image digests, commit ids)
CIRCLECI_LONG = """version: 2.1

orbs:
  deploy: example/deploy-orb@1.2.0
  node: example/node-tools@4.7.1
  notify: example/chat-notify@2.0.3

parameters:
  run_integration:
    type: boolean
    default: false
  release_channel:
    type: enum
    enum: [stable, beta, canary]
    default: stable
  pinned_commit:
    type: string
    default: "72fcf96f4cce48a1580a1fb55d32933fa6f1661f"
  node_version:
    type: string
    default: "20.11"

executors:
  node:
    docker:
      - image: cimg/node@sha256:237b647edc1e2b25e8c303fa128e366162dbb960b9c796d0d1267342d7242659
    resource_class: medium
    working_directory: ~/app
  deployer:
    docker:
      - image: cimg/aws@sha256:39f7e04f389e60737b4cfd3cf78c88431006b6cd236e2286859b9dab9893ba5b
    resource_class: small

commands:
  restore_deps:
    steps:
      - restore_cache:
          keys:
            - v3-deps-{{ arch }}-{{ checksum "package-lock.json" }}
            - v3-deps-{{ arch }}-
  save_deps:
    steps:
      - save_cache:
          key: v3-deps-{{ arch }}-{{ checksum "package-lock.json" }}
          paths:
            - node_modules
            - ~/.npm

jobs:
  lint:
    executor: node
    steps:
      - checkout
      - restore_deps
      - run: npm ci --prefer-offline --no-audit
      - save_deps
      - run: npm run lint -- --max-warnings 0
  unit:
    executor: node
    parallelism: 4
    steps:
      - checkout
      - restore_deps
      - run: npm ci --prefer-offline --no-audit
      - run:
          name: Unit tests
          command: npx jest --ci --shard=$((CIRCLE_NODE_INDEX + 1))/$CIRCLE_NODE_TOTAL --reporters=default --reporters=jest-junit
      - store_test_results:
          path: reports/junit
  integration:
    executor: node
    steps:
      - checkout
      - restore_deps
      - run: npm ci --prefer-offline --no-audit
      - run:
          name: Integration tests against the staging API
          command: |
            export API_BASE_URL="$(aws ssm get-parameter --name /example/app/staging/api_base_url --query Parameter.Value --output text)"
            export DB_PASSWORD_PARAM=/example/app/staging/db_password
            npm run test:integration -- --timeout 120000
  build:
    executor: node
    steps:
      - checkout
      - restore_deps
      - run: npm ci --prefer-offline --no-audit
      - run:
          name: Build bundle
          command: |
            echo "building << pipeline.parameters.pinned_commit >> for << pipeline.parameters.release_channel >>"
            npm run build -- --mode production
            sha256sum dist/*.js > dist/SHA256SUMS
      - save_cache:
          key: v2-build-{{ .Environment.CIRCLE_SHA1 }}-0eb3e01e5294029bafcd012fabb982e09de9b1db
          paths:
            - dist
      - persist_to_workspace:
          root: .
          paths: [dist]
  publish:
    executor: deployer
    steps:
      - attach_workspace:
          at: .
      - run:
          name: Read release settings from the parameter store
          command: |
            aws ssm get-parameters-by-path --path /example/app/prod/ --recursive --query "Parameters[].Name" --output text
            aws ssm get-parameter --name /example/app/prod/cdn_distribution_id --query Parameter.Value --output text > .cdn_id
      - deploy/release:
          bucket: s3://example-app-releases
          source: dist
          cache_control: "public, max-age=31536000, immutable"
      - notify/status:
          channel: releases
          only_on_fail: true

workflows:
  main:
    jobs:
      - lint
      - unit:
          requires: [lint]
      - integration:
          requires: [unit]
          context: [example-aws-staging, example-npm-read]
          filters:
            branches:
              only: [main, /release\\/.*/]
      - build:
          requires: [unit]
          context: example-npm-read
      - hold_for_approval:
          type: approval
          requires: [build, integration]
      - publish:
          requires: [hold_for_approval]
          context: [example-aws-prod, example-chat-webhook]
          filters:
            branches:
              only: main
  nightly:
    triggers:
      - schedule:
          cron: "17 3 * * *"
          filters:
            branches:
              only: main
    jobs:
      - unit
      - integration:
          context: [example-aws-staging, example-npm-read]
"""
CIRCLECI_LONG_RESPONSE = rec("200 OK", CIRCLECI_LONG, "Content-Type: text/plain")
# a long invented Prometheus body: the same version series first, then many labelled series with high-cardinality
# labels (pod names, routes, histogram buckets) and long numeric values, none of them secret
METRICS_LONG = (
    "# HELP demoapp_version_info Application version.\n# TYPE demoapp_version_info gauge\n"
    "demoapp_version_info{version=\"v3.1.4\",major=\"3\",minor=\"1\",patch=\"4\",commit=\"0eb3e01e5294029bafcd012fabb982e09de9b1db\"} 1\n"
    "# HELP demoapp_nodejs_version_info Node.js version.\n# TYPE demoapp_nodejs_version_info gauge\n"
    "demoapp_nodejs_version_info{version=\"v20.11.1\"} 1\n"
    "# HELP demoapp_process_start_time_seconds Start time of the process since unix epoch in seconds.\n"
    "# TYPE demoapp_process_start_time_seconds gauge\ndemoapp_process_start_time_seconds 1903715482.61\n"
    "# HELP demoapp_process_resident_memory_bytes Resident memory size in bytes.\n"
    "# TYPE demoapp_process_resident_memory_bytes gauge\ndemoapp_process_resident_memory_bytes 318767104\n"
    "# HELP demoapp_http_requests_total Requests served.\n# TYPE demoapp_http_requests_total counter\n"
    + "".join(f"demoapp_http_requests_total{{pod=\"demoapp-web-{pod}\",method=\"{m}\",route=\"{r}\",code=\"{c}\"}} {n}\n"
              for pod, n0 in (("d8b01f54bc-4xk2p", 48213907), ("bba1ae0687-q7nzw", 51730264), ("5f7cf52f5f-mj9tc", 39904418))
              for (m, r, c, n) in (("GET", "/api/v1/items/:id", "200", n0), ("GET", "/api/v1/items", "200", n0 // 3),
                                   ("POST", "/api/v1/orders", "201", n0 // 17), ("GET", "/api/v1/items/:id", "404", n0 // 211),
                                   ("POST", "/api/v1/session", "401", n0 // 389), ("GET", "/healthz", "200", n0 * 2)))
    + "# HELP demoapp_http_request_duration_seconds Request latency.\n# TYPE demoapp_http_request_duration_seconds histogram\n"
    + "".join(f"demoapp_http_request_duration_seconds_bucket{{pod=\"demoapp-web-d8b01f54bc-4xk2p\",route=\"/api/v1/items/:id\",le=\"{le}\"}} {n}\n"
              for le, n in (("0.005", 1180342), ("0.01", 9215730), ("0.025", 30117952), ("0.05", 44890213), ("0.1", 47702688),
                            ("0.25", 48120774), ("0.5", 48198301), ("1", 48211850), ("2.5", 48213790), ("+Inf", 48213907)))
    + "demoapp_http_request_duration_seconds_sum{pod=\"demoapp-web-d8b01f54bc-4xk2p\",route=\"/api/v1/items/:id\"} 1052338.4471925\n"
    "demoapp_http_request_duration_seconds_count{pod=\"demoapp-web-d8b01f54bc-4xk2p\",route=\"/api/v1/items/:id\"} 48213907\n"
    "# HELP demoapp_cache_entries Entries per cache shard.\n# TYPE demoapp_cache_entries gauge\n"
    + "".join(f"demoapp_cache_entries{{shard=\"{s:02d}\",tenant=\"tenant-{t}\"}} {e}\n"
              for s, t, e in ((0, "55ef8b43", 187340), (1, "63040013", 92211), (2, "ad2aac15", 1408833), (3, "a96a3731", 73), (4, "55ef8b43", 660192)))
    + "# HELP demoapp_queue_lag_seconds Consumer lag.\n# TYPE demoapp_queue_lag_seconds gauge\n"
    "demoapp_queue_lag_seconds{queue=\"orders\",partition=\"7\"} 0.000183746\n"
    "demoapp_queue_lag_seconds{queue=\"orders\",partition=\"11\"} 12.9930571\n"
    "demoapp_queue_lag_seconds{queue=\"emails\",partition=\"0\"} 3.4e-05\n"
    "# HELP demoapp_db_pool_connections Pool connections by state.\n# TYPE demoapp_db_pool_connections gauge\n"
    "demoapp_db_pool_connections{pool=\"primary\",state=\"idle\"} 14\ndemoapp_db_pool_connections{pool=\"primary\",state=\"busy\"} 6\n"
    "demoapp_db_pool_connections{pool=\"replica\",state=\"idle\"} 22\ndemoapp_db_pool_connections{pool=\"replica\",state=\"busy\"} 2\n"
    "# HELP demoapp_nodejs_heap_size_used_bytes Heap used.\n# TYPE demoapp_nodejs_heap_size_used_bytes gauge\n"
    "demoapp_nodejs_heap_size_used_bytes 147851264\ndemoapp_nodejs_gc_duration_seconds_sum{kind=\"major\"} 18.402995117\n"
    "demoapp_nodejs_eventloop_lag_p99_seconds 0.012058623\n")
METRICS_LONG_RESPONSE = rec("200 OK", METRICS_LONG, "Content-Type: text/plain; version=0.0.4")
# .svn/wc.db: nuclei matched on the SQLite magic; the code never parses the recorded body (it re-fetches the file),
# so only the 16-byte magic and an empty header are kept
SVN_REQUEST = req("/.svn/wc.db", "app5.alpha.example")
SVN_RESPONSE = rec("200 OK", "SQLite format 3\x00" + "\x00" * 84, "Content-Type: application/octet-stream")

# ---- made-up secrets (same shape as the real ones); none may ever appear in a triage output string
FAKE_NPM = "npm_FAKEfakeFAKEfake0123456789abcdefABCD"
FAKE_REG = "FAKE0000-1111-2222-3333-444455556666"
FAKE_PW = "Fak3Passw0rdXYZ"
FAKE_MCP = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0123"
FAKE_GKEY = "AIzaFAKEfakeFAKEfakeFAKEfakeFAKEfake123"
FAKES = (FAKE_NPM, FAKE_REG, FAKE_PW, FAKE_MCP, FAKE_GKEY)
NPMRC = ("@ui:registry=https://npm.example.com/\n"
         f"//npm.example.com/:_authToken={FAKE_REG}\n"
         "@example:registry=https://example-000000000000.d.codeartifact.us-east-1.amazonaws.com/npm/private/\n"
         f"//example-000000000000.d.codeartifact.us-east-1.amazonaws.com/npm/private/:_authToken={FAKE_NPM}\n").encode()
BUILD_SH = b"#!/bin/bash\nset -e\nnpm run build --workspaces\ncp -r dist/* public/\n"

def strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            yield str(k); yield from strings(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            yield from strings(v)
    elif x is not None:
        yield str(x)

class Stub:
    """fetch(url, headers[, data]) -> (status, final_url, body); unknown URLs on the host get 404; off-host is a test failure."""
    def __init__(self, host, table=None):
        self.host, self.table, self.calls = host, table or {}, []
    def __call__(self, url, headers, data=None):
        self.calls.append((url, data))
        if urllib.parse.urlsplit(url).hostname != self.host:
            raise AssertionError(f"off-host fetch {url}")
        r = self.table.get(url, (404, b"<html><head><title>404 Not Found</title></head><body>Not Found</body></html>"))
        if isinstance(r, Exception):
            raise r
        return r[0], url, r[1]

def nuclei(tid, url, host, request="", response="", tags=(), pci=False):
    f = {"source": "nuclei", "check_id": tid, "tags": list(tags), "matched": url, "hostname": host, "pci": pci, "title": tid}
    raw = {"template-id": tid, "matched-at": url, "request": request, "response": response}
    return f, raw

def resp(status_line, body, headers=("Content-Type: text/plain",)):
    return "HTTP/1.1 " + status_line + "\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n" + body

KEYS = {"exposure", "summary", "fix", "items", "secrets", "pci"}

class Base(unittest.TestCase):
    def check(self, t):
        self.assertEqual(set(t), KEYS)
        self.assertIn(t["exposure"], T.EXPOSURES)
        self.assertTrue(t["summary"]); self.assertTrue(t["fix"])
        self.assertLessEqual(len(t["items"]), T.MAX_ITEMS)
        for it in t["items"]:
            self.assertEqual(set(it), {"url", "status", "bytes", "kind", "note"})
        for s in t["secrets"]:
            # a secret found by pattern also carries its masked form (public prefix and length only)
            self.assertLessEqual({"type", "where", "line"}, set(s)); self.assertLessEqual(set(s), {"type", "where", "line", "masked"})
            if "masked" in s:   # a public prefix at most, then only the length
                self.assertRegex(s["masked"], r"^(?:-----BEGIN [A-Z0-9 ]+-----|AKIA|ASIA|gh[pousr]_|npm_|xox[abprs]-|[sr]k_live_|AIza|eyJ)?\.\.\.\[\d+ chars\]$")
        blob = "\n".join(strings(t))
        for v in FAKES:
            self.assertNotIn(v, blob)
        return t

class TestDockerfile(Base):
    def test_app_dockerfile_finds_the_npmrc(self):
        f, raw = nuclei("dockerfile-hidden-disclosure", "https://app1.alpha.example:443/Dockerfile", "app1.alpha.example", DOCKER_REQUEST, DOCKER_RESPONSE,
                        ("exposure", "devops", "docker"))
        b = "https://app1.alpha.example:443/"
        stub = Stub("app1.alpha.example", {b + ".npmrc": (200, NPMRC), b + "build.sh": (200, BUILD_SH),
                                          b + "package.json": (403, b"Forbidden"), b + "settings.php": (403, b"Forbidden"),
                                          b + "settings.dist.php": (403, b"Forbidden"), b + ".git/config": (403, b"Forbidden")})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "credential")
        npmrc = [it for it in t["items"] if it["url"].endswith("/.npmrc")]
        self.assertEqual(len(npmrc), 1); self.assertEqual(npmrc[0]["kind"], "credential"); self.assertEqual(npmrc[0]["status"], 200)
        self.assertEqual([s["type"] for s in t["secrets"]], ["npm registry token"] * 2)
        self.assertTrue(all(s["where"] == "/.npmrc" for s in t["secrets"]))
        self.assertIn(".npmrc", t["summary"]); self.assertIn("2 npm registry tokens", t["summary"])
        self.assertIn("111122223333", " ".join(it["note"] for it in t["items"]))
        self.assertIn("Revoke", t["fix"]); self.assertIn("/build", t["fix"])
        fetched = [u for u, _ in stub.calls]
        self.assertLessEqual(len(fetched), T.MAX_FETCHES)
        self.assertEqual(fetched[:4], [b + ".npmrc", b + "package.json", b + "package-lock.json", b + "build.sh"])
        self.assertIn(b + "settings.dist.php", fetched)
        self.assertEqual([it["kind"] for it in t["items"] if it["url"].endswith("build.sh")], ["source"])

    def test_html_catch_all_is_not_the_file(self):
        f, raw = nuclei("dockerfile-hidden-disclosure", "https://spa.example.test/Dockerfile", "spa.example.test",
                        response=resp("200 OK", "FROM node:20\nCOPY .npmrc ./\n"))
        page = b"<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"
        stub = Stub("spa.example.test", {"https://spa.example.test/.npmrc": (200, page)})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "internal")
        self.assertEqual(t["secrets"], [])

    def test_matched_url_on_another_host_is_never_fetched(self):
        f, raw = nuclei("dockerfile-hidden-disclosure", "https://other.example.test/Dockerfile", "mine.example.test",
                        response=resp("200 OK", "FROM node:20\nCOPY .npmrc ./\n"))
        stub = Stub("other.example.test")
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(stub.calls, [])
        self.assertTrue(any(it["kind"] == "skipped" for it in t["items"]))

class TestCompose(Base):
    def test_compose_env_file_and_mounts(self):
        f, raw = nuclei("docker-compose-config", "https://app2.alpha.example:443/docker-compose.yml", "app2.alpha.example",
                        COMPOSE_REQUEST, COMPOSE_RESPONSE)
        env = f"APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASSWORD={FAKE_PW}\n".encode()
        stub = Stub("app2.alpha.example", {"https://app2.alpha.example:443/config/.env": (200, env)})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual([u for u, _ in stub.calls], ["https://app2.alpha.example:443/config/.env"])
        self.assertEqual(t["exposure"], "credential")
        self.assertIn(".aws/credentials", t["summary"])
        self.assertEqual(t["secrets"][0]["where"], "/config/.env")

    def test_env_file_not_readable(self):
        f, raw = nuclei("docker-compose-config", "https://app2.alpha.example:443/docker-compose.yml", "app2.alpha.example",
                        COMPOSE_REQUEST, COMPOSE_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app2.alpha.example")))
        self.assertEqual(t["exposure"], "internal")

    def test_inline_secret(self):
        body = f"services:\n  db:\n    image: mysql:8\n    environment:\n      - MYSQL_ROOT_PASSWORD={FAKE_PW}\n      - MYSQL_DATABASE=app\n"
        f, raw = nuclei("docker-compose-config", "https://c.example.test/docker-compose.yml", "c.example.test", response=resp("200 OK", body))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("c.example.test")))
        self.assertEqual(t["exposure"], "credential")
        self.assertEqual(t["secrets"][0]["type"], "inline secret in environment")

class TestCI(Base):
    def test_circleci_orb_listed_without_secrets(self):
        f, raw = nuclei("circleci-config", "http://app3.alpha.example:80/.circleci/config.yml", "app3.alpha.example",
                        CIRCLECI_REQUEST, CIRCLECI_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app3.alpha.example")))
        self.assertEqual(t["exposure"], "internal")
        self.assertIn("example/deploy-orb", t["summary"])
        self.assertEqual(t["secrets"], [])

    def test_long_circleci_config_without_secrets(self):
        # false-positive guard: parameter-store paths, contexts, cache keys, digests and commit ids are not secrets
        self.assertGreater(len(CIRCLECI_LONG), 3000)
        f, raw = nuclei("circleci-config", "http://app3.alpha.example:80/.circleci/config.yml", "app3.alpha.example",
                        CIRCLECI_REQUEST, CIRCLECI_LONG_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app3.alpha.example")))
        self.assertEqual(t["exposure"], "internal")
        self.assertIn("example/deploy-orb", t["summary"])
        self.assertEqual(t["secrets"], [])

    def test_inline_secret_and_script(self):
        body = f"deploy:\n  script:\n    - export AWS_SECRET_ACCESS_KEY={FAKE_PW}\n    - ./scripts/deploy.sh s3://acme-builds\n"
        f, raw = nuclei("gitlab-ci-config", "https://g.example.test/.gitlab-ci.yml", "g.example.test", response=resp("200 OK", body))
        stub = Stub("g.example.test", {"https://g.example.test/scripts/deploy.sh": (200, b"#!/bin/sh\nset -e\naws s3 sync dist s3://acme-builds\n")})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "credential")
        self.assertIn("acme-builds", t["summary"])
        self.assertIn("deploy.sh", t["summary"])

class TestGit(Base):
    G = "https://app4.alpha.example:443/.git/"
    def test_git_dumpable(self):
        f, raw = nuclei("git-config", self.G + "config", "app4.alpha.example", GITCFG_REQUEST, GITCFG_RESPONSE)
        idx = b"DIRC" + struct.pack(">II", 2, 42) + b"\x00" * 64
        logs = b"0" * 40 + b" " + b"1" * 40 + b" Dev One <dev1@example.test> 1600000000 +0000\tclone: from https://git.alpha.example/web/app.git\n"
        stub = Stub("app4.alpha.example", {self.G + "HEAD": (200, b"ref: refs/heads/master\n"), self.G + "index": (200, idx), self.G + "logs/HEAD": (200, logs)})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "source")
        self.assertIn("refs/heads/master", t["summary"]); self.assertIn("42 files", t["summary"])
        self.assertIn("git.alpha.example", " ".join(it["note"] for it in t["items"]))
        self.assertIn("dev1@example.test", " ".join(it["note"] for it in t["items"]))
        self.assertEqual(len(stub.calls), 4)

    def test_head_only_is_not_dumpable(self):
        f, raw = nuclei("git-config", self.G + "config", "app4.alpha.example", GITCFG_REQUEST, GITCFG_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app4.alpha.example", {self.G + "HEAD": (200, b"ref: refs/heads/master\n")})))
        self.assertEqual(t["exposure"], "internal")

    def test_credential_in_remote(self):
        body = f'[remote "origin"]\n\turl = https://deploy:{FAKE_PW}@git.example.test/app.git\n'
        f, raw = nuclei("git-config", "https://r.example.test/.git/config", "r.example.test", response=resp("200 OK", body))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("r.example.test")))
        self.assertEqual(t["exposure"], "credential")
        self.assertEqual(t["secrets"][0]["type"], "credential in git remote URL")
        self.assertIn("git.example.test", " ".join(it["note"] for it in t["items"]))

class TestSvn(Base):
    def wcdb(self, files):
        fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
        db = sqlite3.connect(p)
        db.execute("CREATE TABLE REPOSITORY(id INTEGER PRIMARY KEY, root TEXT, uuid TEXT)")
        db.execute("CREATE TABLE NODES(wc_id INTEGER, local_relpath TEXT, op_depth INTEGER, kind TEXT, checksum TEXT)")
        db.execute("INSERT INTO REPOSITORY VALUES(1, 'https://svn.example.test/repos/app', 'uuid')")
        for rel, ck in files:
            db.execute("INSERT INTO NODES VALUES(1, ?, 0, 'file', ?)", (rel, ck))
        db.commit(); db.close()
        with open(p, "rb") as fh:
            data = fh.read()
        os.unlink(p)
        return data

    def test_wcdb_pristine_readable(self):
        sha = "ab" + "c" * 38
        data = self.wcdb([("index.php", "$sha1$" + "d" * 40), ("config/db.php", "$sha1$" + sha), ("README", None)])
        u = "https://app5.alpha.example:443/.svn/wc.db"
        f, raw = nuclei("svn-wc-db", u, "app5.alpha.example", SVN_REQUEST, SVN_RESPONSE)
        stub = Stub("app5.alpha.example", {u: (200, data), f"https://app5.alpha.example:443/.svn/pristine/ab/{sha}.svn-base": (200, f"<?php\n$db_password = '{FAKE_PW}';\n".encode())})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "credential")
        self.assertIn("3 file names", t["summary"]); self.assertIn("svn.example.test", t["summary"])
        self.assertIn("pristine copy of config/db.php", " ".join(it["note"] for it in t["items"]))

    def test_wcdb_parse_rejects_non_sqlite(self):
        self.assertEqual(T.wcdb_parse(b"<html>404</html>"), ([], []))

class TestListings(Base):
    def test_config_listing(self):
        u = "http://app6.alpha.example:80/config/"
        f, raw = nuclei("configuration-listing", u, "app6.alpha.example", "", CONFLIST_RESPONSE, ("config", "listing", "exposure"))
        stub = Stub("app6.alpha.example", {u + "config.php": (200, b""), u + "config.php.dist": (200, f"<?php\n$db_pass = '{FAKE_PW}';\n".encode())})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "credential")
        self.assertEqual([c for c, _ in stub.calls], [u + "config.php.dist", u + "config.php"])   # .dist ranks first
        self.assertIn("config.php.dist", t["summary"]); self.assertIn("Options -Indexes", t["fix"])

    def test_pci_log_listing_goes_into_config(self):
        u = "https://app7.alpha.example:443/log/"
        f, raw = nuclei("directory-listing", u, "app7.alpha.example", "", LOGLIST_RESPONSE, ("listing",), pci=True)
        sub = ('<html><head><title>Index of /log/config</title></head><body><pre><a href="/log/">Parent Directory</a>\n'
               '<a href="db.ini">db.ini</a>\n</pre></body></html>').encode()
        stub = Stub("app7.alpha.example", {u + "config/": (200, sub), u + "config/db.ini": (200, b"[db]\nhost = 10.1.2.3\nport = 3306\n"),
                                                             u + "index.php": (200, b"ok"), u + "upload.php": (200, b"")})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertTrue(t["pci"])
        self.assertIn(u + "config/db.ini", [c for c, _ in stub.calls])
        self.assertIn("PCI", t["fix"])
        self.assertEqual(t["exposure"], "config")
        self.assertLessEqual(len(stub.calls), T.MAX_FETCHES)

    def test_budget_and_offhost(self):
        names = [f"f{i}.txt" for i in range(30)]
        body = "<html><title>Index of /x</title><body><pre>" + "".join(f'<a href="{n}">{n}</a>\n' for n in names) + \
               '<a href="https://evil.example.test/a.env">a.env</a>\n</pre></body></html>'
        f, raw = nuclei("configuration-listing", "https://l.example.test/x/", "l.example.test", response=resp("200 OK", body, ["Content-Type: text/html"]))
        stub = Stub("l.example.test")
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(len(stub.calls), T.MAX_FETCHES)
        self.assertEqual(t["exposure"], "names")

    def test_negotiation_config_rb(self):
        r = resp("406 Not Acceptable", "Available variants:\n<ul>\n<li><a href=\"config.rb\">config.rb</a></li>\n</ul>",
                 ['Alternates: {"config.rb" 1 {type application/x-ruby}}'])
        f, raw = nuclei("apache-mod-negotiation-listing", "https://app.example.test:443/config", "app.example.test", response=r)
        stub = Stub("app.example.test", {"https://app.example.test:443/config.rb": (200, b"require 'compass'\nhttp_path = '/'\ncss_dir = 'css'\ndef x\nend\n")})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(t["exposure"], "source")
        self.assertIn("MultiViews", t["fix"])

class TestClaude(Base):
    def test_wiki_agents_index_is_a_login_page(self):
        f, raw = nuclei("claude-code-agents", "https://wiki.alpha.example:443/.claude/agents/index.md", "wiki.alpha.example", CLAUDE_REQUEST, CLAUDE_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("wiki.alpha.example")))
        self.assertEqual(t["exposure"], "nothing")
        self.assertIn("login", t["summary"])

    # the other three login markers redact.html_kind accepts, one per page, none with a password field
    def wiki_page(self, html):
        self.assertNotRegex(html.lower(), r"<input[^>]+type=[\"']?password")
        response = rec("200 OK", html, "Content-Type: text/html; charset=utf-8")
        f, raw = nuclei("claude-code-agents", "https://wiki.alpha.example:443/.claude/agents/index.md", "wiki.alpha.example", CLAUDE_REQUEST, response)
        return self.check(T.triage(f, raw, "confirmed", fetch=Stub("wiki.alpha.example")))

    def test_do_login_link_is_a_login_page(self):
        html = ("<!DOCTYPE html>\n<html><head><title>Wiki - agents/index.md</title></head>\n<body>\n"
                "<p>This topic does not exist yet.</p>\n<a href=\"/doku.php?id=agents:index&amp;do=login\" rel=\"nofollow\">Sign in</a>\n</body></html>\n")
        self.assertEqual(T.R.html_kind(html), "login")
        self.assertEqual(T.R.classify(html, "wiki/start.php"), ("nothing", "HTML login page"))
        t = self.wiki_page(html)
        self.assertEqual(t["exposure"], "nothing")
        self.assertIn("login", t["summary"])

    def test_mode_denied_body_is_a_login_page(self):
        html = ("<!DOCTYPE html>\n<html><head><title>Wiki - agents/index.md</title></head>\n<body>\n"
                "<div class=\"dokuwiki mode_denied\">\n<p>Sorry, you do not have enough rights to continue.</p>\n</div>\n</body></html>\n")
        self.assertEqual(T.R.html_kind(html), "login")
        self.assertEqual(T.R.classify(html, "wiki/start.php"), ("nothing", "HTML login page"))
        t = self.wiki_page(html)
        self.assertEqual(t["exposure"], "nothing")
        self.assertIn("login", t["summary"])

    def test_permission_denied_title_is_a_login_page(self):
        html = ("<!DOCTYPE html>\n<html><head><title>Permission Denied - Wiki</title></head>\n<body>\n"
                "<p>You are not allowed to view this topic.</p>\n</body></html>\n")
        self.assertEqual(T.R.html_kind(html), "login")
        self.assertEqual(T.R.classify(html, "wiki/start.php"), ("nothing", "HTML login page"))
        t = self.wiki_page(html)
        self.assertEqual(t["exposure"], "nothing")
        self.assertIn("login", t["summary"])

    def test_page_without_a_login_marker_is_not_a_login_page(self):
        html = ("<!DOCTYPE html>\n<html><head><title>Wiki - agents/index.md</title></head>\n<body>\n"
                "<h1>Agents</h1>\n<p>Notes about the build agents.</p>\n</body></html>\n")
        self.assertEqual(T.R.html_kind(html), "page")
        self.assertNotEqual(T.R.classify(html, "wiki/start.php")[1], "HTML login page")
        t = self.wiki_page(html)
        self.assertEqual(t["exposure"], "nothing")   # still not the file: the dot path answered with an HTML page
        self.assertNotIn("login", t["summary"])

    def test_settings_with_mcp_token(self):
        body = json.dumps({"permissions": {"allow": ["Bash(npm run *)", "Read(/home/user/app/**)"]}, "env": {"NODE_ENV": "production"},
                           "mcpServers": {"github": {"command": "gh-mcp", "env": {"GITHUB_TOKEN": FAKE_MCP}}}}, indent=1)
        f, raw = nuclei("claude-settings-exposure", "https://x.example.test/.claude/settings.local.json", "x.example.test", response=resp("200 OK", body, ["Content-Type: application/json"]))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("x.example.test")))
        self.assertEqual(t["exposure"], "credential")
        self.assertIn("MCP server github", " ".join(s["type"] for s in t["secrets"]))
        self.assertIn("/home/user/app", t["summary"])

class TestMetrics(Base):
    def test_metrics_versions(self):
        f, raw = nuclei("prometheus-metrics", "https://app9.alpha.example:443/metrics", "app9.alpha.example", METRICS_REQUEST, METRICS_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app9.alpha.example")))
        self.assertEqual(t["exposure"], "internal")
        self.assertIn("demoapp v3.1.4", t["summary"])
        self.assertIn("authentication", t["fix"])

    def test_long_metrics_body_without_secrets(self):
        # false-positive guard: high-cardinality labels and long numeric values are not secrets
        self.assertGreater(len(METRICS_LONG), 3000)
        f, raw = nuclei("prometheus-metrics", "https://app9.alpha.example:443/metrics", "app9.alpha.example", METRICS_REQUEST, METRICS_LONG_RESPONSE)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app9.alpha.example")))
        self.assertEqual(t["exposure"], "internal")
        self.assertIn("demoapp v3.1.4", t["summary"])
        self.assertIn("authentication", t["fix"])
        self.assertEqual(t["secrets"], [])

    def test_secret_in_label(self):
        body = f'up{{job="api",instance="10.0.0.1:9100"}} 1\nfoo_info{{dsn="postgres://app:{FAKE_PW}@db.internal:5432/app"}} 1\n'
        f, raw = nuclei("grafana-metrics-exposure", "https://m.example.test/metrics", "m.example.test", response=resp("200 OK", body))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("m.example.test")))
        self.assertEqual(t["exposure"], "credential")
        self.assertIn("1 jobs", t["summary"])

class TestSingleResponse(Base):
    def test_phpinfo_key_names_only(self):
        rows = (f'<tr><td class="e">$_SERVER[\'DB_PASSWORD\']</td><td class="v">{FAKE_PW}</td></tr>'
                '<tr><td class="e">$_SERVER[\'APP_ENV\']</td><td class="v">production</td></tr>'
                '<tr><td class="e">DOCUMENT_ROOT </td><td class="v">/var/www/html </td></tr>')
        body = f"<html><body><h1 class=\"p\">PHP Version 7.4.33</h1><table>{rows}</table></body></html>"
        f, raw = nuclei("phpinfo-files", "https://p.example.test/phpinfo.php", "p.example.test", response=resp("200 OK", body, ["Content-Type: text/html"]))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("p.example.test")))
        self.assertEqual(t["exposure"], "credential")
        self.assertEqual(t["secrets"], [{"type": "secret in PHP environment", "where": "DB_PASSWORD", "line": 0}])
        self.assertIn("PHP 7.4.33", t["summary"])

    def test_phpinfo_tokenizer_is_not_a_secret(self):
        body = ('<html><body><h1 class="p">PHP Version 8.2.27</h1><table><tr><td class="e">Tokenizer Support </td><td class="v">enabled </td></tr>'
                '<tr><td class="e">tokenizer</td><td class="v">enabled</td></tr></table></body></html>')
        f, raw = nuclei("phpinfo-files", "https://p.example.test/test.php", "p.example.test", response=resp("200 OK", body, ["Content-Type: text/html"]))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("p.example.test")))
        self.assertEqual((t["exposure"], t["secrets"]), ("internal", []))

    def test_empty_php_output_is_served_not_unreadable(self):
        u = "http://app6.alpha.example:80/config/"
        f, raw = nuclei("configuration-listing", u, "app6.alpha.example", "", CONFLIST_RESPONSE, ("config", "listing", "exposure"))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app6.alpha.example", {u + "config.php": (200, b""), u + "config.php.dist": (200, b"")})))
        self.assertIn("served but nothing of note: config/config.php.dist (0 bytes)", t["summary"])
        self.assertNotIn("not readable", t["summary"])

    def test_web_config_connection_string(self):
        body = f"<configuration><connectionStrings><add name='db' connectionString='Server=sql1;User Id=app;Password={FAKE_PW};'/></connectionStrings></configuration>"
        f, raw = nuclei("web-config", "https://w.example.test/web.config", "w.example.test", response=resp("200 OK", body))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("w.example.test")))
        self.assertEqual(t["exposure"], "credential")

    def test_graphiql_introspection(self):
        f, raw = nuclei("graphiql-exposure", "https://g.example.test/graphiql", "g.example.test", response=resp("200 OK", "<html>graphiql</html>"))
        stub = Stub("g.example.test", {"https://g.example.test/graphql": (200, json.dumps({"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}).encode())})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual(len(stub.calls), 1); self.assertIn(b"__schema", stub.calls[0][1])
        self.assertIn("2 types", t["summary"])

    def test_google_key_no_value(self):
        f, raw = nuclei("google-api-key", "https://app.example.test:443", "app.example.test", response=resp("200 OK", f"<script>var k='{FAKE_GKEY}';</script>"))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("app.example.test")))
        self.assertEqual(t["exposure"], "credential")
        self.assertEqual(t["secrets"][0]["type"], "Google API key")
        self.assertIn("restrict", t["fix"])

    def test_ds_store_names_fetched(self):
        def rec(name):
            return b"\x00\x00\x00" + bytes([len(name)]) + name.encode("utf-16-be") + b"Iloc" + b"blob" + b"\x00" * 8
        data = b"\x00\x00\x00\x01Bud1" + b"\x00" * 20 + rec("backup.sql") + rec("logo.png") + rec("images")
        u = "https://assets.example.test/.DS_Store"
        f, raw = nuclei("ds-store-file", u, "assets.example.test", response=resp("200 OK", "lossy"))
        stub = Stub("assets.example.test", {u: (200, data), "https://assets.example.test/backup.sql": (200, b"CREATE TABLE users(id int, email text);\nINSERT INTO users VALUES(1,'a@example.test');\n")})
        t = self.check(T.triage(f, raw, "confirmed", fetch=stub))
        self.assertEqual([c for c, _ in stub.calls][:2], [u, "https://assets.example.test/backup.sql"])
        self.assertIn("backup.sql", t["summary"])
        self.assertNotIn("https://assets.example.test/images", [c for c, _ in stub.calls])

    def test_package_json(self):
        body = json.dumps({"name": "sample-ui", "version": "2.4.0", "dependencies": {"left-pad": "1.3.0", "@example/ui": "2.0.0"}})
        f, raw = nuclei("package-json", "https://c.example.test/package.json", "c.example.test", response=resp("200 OK", body))
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("c.example.test")))
        self.assertEqual(t["exposure"], "internal")
        self.assertIn("sample-ui 2.4.0", t["summary"])

    def test_laravel_debug(self):
        f, raw = nuclei("laravel-debug-enabled", "https://s.example.test/_ignition/health-check", "s.example.test", response=resp("200 OK", '{"can_execute_commands":true}'))
        t = self.check(T.triage(f, raw, None, fetch=Stub("s.example.test")))
        self.assertEqual(t["exposure"], "config")
        self.assertIn("APP_DEBUG=false", t["fix"])

class TestDebugHeaders(Base):
    def test_fastly_debug(self):
        r = resp("200 OK", "<html><title>w</title></html>", ["Content-Type: text/html", "Fastly-Debug-Path: (D cache-iad-1 1700000000) (F cache-iad-2 1)", "Fastly-Debug-TTL: (H cache-iad-1 - - 10)"])
        f, raw = nuclei("fastly-debug-headers", "https://w.example.test:443", "w.example.test", response=r)
        t = self.check(T.triage(f, raw, "confirmed", fetch=Stub("w.example.test")))
        self.assertEqual(t["exposure"], "internal"); self.assertIn("fastly-debug-path", t["summary"]); self.assertIn("vcl", t["fix"])

class TestXss(Base):
    def test_login_page_reflects_u(self):
        u = "https://web1.alpha.example:443/?u=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-u%27%29%3E"
        f, raw = nuclei("xss-fuzz", u, "web1.alpha.example", XSS_REQUEST, XSS_RESPONSE, ("xss", "fuzz"))
        stub = Stub("web1.alpha.example")
        t = self.check(T.triage(f, raw, None, fetch=stub))
        self.assertEqual(stub.calls, [])
        self.assertEqual(t["exposure"], "source")
        self.assertIn("parameter u", t["summary"])
        note = t["items"][0]["note"]
        self.assertIn("[payload]", note); self.assertNotIn("confirm(", note)
        self.assertIn("login page", t["summary"])

    def test_escaped_payload_is_not_confirmed(self):
        body = "<html><body><input value=\"&#39;&gt;&quot;&lt;svg/onload=confirm(&#39;xss-u&#39;)&gt;\"></body></html>"
        f, raw = nuclei("xss-fuzz", "https://e.example.test/?u=x", "e.example.test", response=resp("200 OK", body, ["Content-Type: text/html"]))
        t = self.check(T.triage(f, raw, None, fetch=Stub("e.example.test")))
        self.assertEqual(t["exposure"], "nothing")

    def test_json_reflection_is_not_confirmed(self):
        body = '{"q":"\'>\\"<svg/onload=confirm(\'xss-q\')>"}'
        f, raw = nuclei("xss-fuzz", "https://j.example.test/?q=x", "j.example.test", response=resp("200 OK", body, ["Content-Type: application/json"]))
        self.assertEqual(self.check(T.triage(f, raw, None, fetch=Stub("j.example.test")))["exposure"], "nothing")

class TestPorts(Base):
    def port_finding(self, port, ip):
        return ({"source": "nmap", "check_id": f"{port}/tcp", "port": port, "matched": f"{ip}:{port}", "hostname": "db.example.test", "pci": False, "title": "x"},
                {"ip": ip, "port": port, "proto": "tcp", "service": "", "product": ""})

    def test_mysql_1130(self):
        payload = b"\xff" + (1130).to_bytes(2, "little") + b"Host '203.0.113.47' is not allowed to connect to this MySQL server"
        pkt = len(payload).to_bytes(3, "little") + b"\x00" + payload
        self.assertEqual(T.mysql_parse(pkt)[0], "rejected")
        f, raw = self.port_finding(3306, "192.0.2.71")
        t = self.check(T.triage(f, raw, None, probe=lambda h, p: T.mysql_parse(pkt)))
        self.assertEqual(t["exposure"], "nothing"); self.assertIn("1130", t["summary"])

    def test_mysql_greeting(self):
        payload = b"\x0a8.0.36\x00" + b"\x01\x00\x00\x00" + b"abcdefgh\x00" + b"\xff\xf7\x21\x02\x00\xff\xc1\x15" + b"\x00" * 10 + b"ijklmnopqrst\x00caching_sha2_password\x00"
        pkt = len(payload).to_bytes(3, "little") + b"\x00" + payload
        kind, detail = T.mysql_parse(pkt)
        self.assertEqual(kind, "auth"); self.assertIn("8.0.36", detail); self.assertIn("caching_sha2_password", detail)

    def test_postgres_pg_hba(self):
        fields = b"SFATAL\x00VFATAL\x00C28000\x00Mno pg_hba.conf entry for host \"203.0.113.47\", user \"scan\", database \"scan\", SSL off\x00Fauth.c\x00\x00"
        pkt = b"E" + struct.pack(">I", len(fields) + 4) + fields
        f, raw = self.port_finding(5432, "192.0.2.188")
        t = self.check(T.triage(f, raw, None, probe=lambda h, p: T.pg_parse(pkt)))
        self.assertEqual(t["exposure"], "nothing"); self.assertIn("pg_hba.conf", t["summary"])
        self.assertNotIn("203.0.113.47", t["summary"])
        self.assertEqual(T.pg_parse(b"R" + struct.pack(">II", 12, 10) + b"SCRAM-SHA-256\x00\x00")[0], "auth")
        self.assertEqual(T.pg_parse(b"R" + struct.pack(">II", 8, 0))[0], "open")

    def test_smb_negotiate(self):
        hdr = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 58
        body = struct.pack("<HHH", 65, 0x03, 0x0302) + b"\x00" * 58
        msg = hdr + body
        pkt = b"\x00" + len(msg).to_bytes(3, "big") + msg
        kind, detail = T.smb_parse(pkt)
        self.assertEqual(kind, "auth"); self.assertIn("3.0.2", detail); self.assertIn("signing required", detail)
        f, raw = self.port_finding(445, "192.0.2.142")
        t = self.check(T.triage(f, raw, None, probe=lambda h, p: T.smb_parse(pkt)))
        self.assertEqual(t["exposure"], "internal")
        self.assertTrue(T.smb_negotiate().startswith(b"\x00"))

    def test_open_without_auth_is_credential(self):
        f, raw = self.port_finding(6379, "198.51.100.230")
        t = self.check(T.triage(f, raw, None, probe=lambda h, p: ("open", "Redis answered PING without AUTH")))
        self.assertEqual(t["exposure"], "credential")

    def test_probe_gets_the_ip(self):
        seen = []
        f, raw = self.port_finding(3306, "192.0.2.71")
        T.triage(f, raw, None, probe=lambda h, p: seen.append((h, p)) or ("nothing", "no answer within 5 s"))
        self.assertEqual(seen, [("192.0.2.71", 3306)])

class TestDispatch(Base):
    def test_wants_triage(self):
        self.assertTrue(T.wants_triage({"source": "nmap", "port": 3306, "check_id": "3306/tcp"}, "Low", None))
        self.assertFalse(T.wants_triage({"source": "nmap", "port": 8081, "check_id": "8081/tcp"}, "Medium", None))
        self.assertTrue(T.wants_triage({"source": "nuclei"}, "Medium", None))
        self.assertTrue(T.wants_triage({"source": "nuclei"}, "Low", "confirmed"))
        self.assertFalse(T.wants_triage({"source": "nuclei"}, "Low", "names_only"))

    def test_legacy_protocol(self):
        f = {"source": "sslscan", "check_id": "legacy-protocol", "port": 443, "hostname": "t.example.test", "pci": False, "title": "x"}
        t = self.check(T.triage(f, {"protocols": ["TLS1.0", "TLS1.1"]}, None))
        self.assertEqual(t["exposure"], "nothing"); self.assertIn("TLS1.0, TLS1.1", t["summary"]); self.assertEqual(t["fix"], T.LEGACY_FIX)

    def test_generic_and_failure_never_raise(self):
        f = {"source": "dns", "check_id": "axfr:ns1", "hostname": "e.test", "title": "Zone transfer allowed", "remediation": "Restrict AXFR."}
        t = self.check(T.triage(f, {}, None))
        self.assertEqual((t["exposure"], t["summary"], t["fix"]), ("unknown", "Zone transfer allowed", "Restrict AXFR."))
        f, raw = nuclei("git-config", "https://b.example.test/.git/config", "b.example.test", response=resp("200 OK", "[core]\n"))
        def boom(url, headers, data=None):
            raise RuntimeError("offline")
        t = self.check(T.triage(f, raw, "confirmed", fetch=boom))
        self.assertIn(t["exposure"], T.EXPOSURES)


# ---------------------------------------------------------------- pinned follow-up fetches and probes
import unittest.mock  # noqa: E402
import safefetch as SF  # noqa: E402
from fakenet import FakeNet, http  # noqa: E402

PHOST = "files.example.test"


def git_finding(host=PHOST, matched=None):
    m = matched or f"http://{host}/.git/config"
    return {"source": "nuclei", "check_id": "git-config", "matched": m, "tags": ["exposure", "config"], "hostname": host}, \
           {"template-id": "git-config", "matched-at": m, "response": "HTTP/1.1 200 OK\r\n\r\n[core]\n"}


class TestPinnedTriage(unittest.TestCase):
    def ctx(self, net, host=PHOST):
        f, raw = git_finding(host)
        return T.Ctx(f, raw, SF.Pinned(host, resolver=net.resolve, connect=net.connect))

    def test_redirect_to_another_host_is_refused(self):
        net = FakeNet([["8.8.8.8"]], [http(301, {"Location": "http://elsewhere.test/x"})])
        st, body = self.ctx(net).get(f"http://{PHOST}/.git/HEAD")
        self.assertIsNone(st)
        self.assertEqual(net.connects, [("8.8.8.8", 80)])

    def test_private_resolution_is_refused(self):
        net = FakeNet([["172.16.4.4"]], [http(200, body="ref: refs/heads/main")])
        c = self.ctx(net)
        self.assertEqual(c.get(f"http://{PHOST}/.git/HEAD"), (None, None))
        self.assertEqual(net.connects, [])
        self.assertEqual(c.items[-1]["kind"], "error")

    def test_address_change_between_lookups_cannot_be_reached(self):
        net = FakeNet([["8.8.4.4"], ["127.0.0.1"]], [http(200, body="ref: refs/heads/main"), http(200, body="x")])
        c = self.ctx(net)
        self.assertEqual(c.get(f"http://{PHOST}/.git/HEAD")[0], 200)
        self.assertEqual(c.get(f"http://{PHOST}/.git/index"), (None, None))
        self.assertEqual(net.connects, [("8.8.4.4", 80)])

    def test_matched_url_host_is_not_used(self):
        f, raw = git_finding(PHOST, matched="http://elsewhere.test/.git/config")
        f["hostname"] = ""
        net = FakeNet([["8.8.8.8"]], [http(200, body="x")])
        c = T.Ctx(f, raw, SF.Pinned("", resolver=net.resolve, connect=net.connect))
        self.assertEqual(c.host, "")
        self.assertEqual(c.get("http://elsewhere.test/.git/HEAD"), (None, None))
        self.assertEqual(net.lookups, [])

    def test_port_probe_refuses_private_and_metadata(self):
        for ip in ("10.0.0.5", "169.254.169.254", "fd00::5"):
            called = []
            with unittest.mock.patch.object(T, "default_probe", side_effect=lambda h, p: called.append(h) or ("auth", "x")):
                t = T.triage({"source": "nmap", "check_id": "3306/tcp", "port": 3306, "hostname": "db.example.test"},
                             {"ip": ip, "port": 3306}, None)
            self.assertEqual(called, [], ip)
            self.assertIn("not probed", t["items"][0]["note"])

    def test_port_probe_uses_checked_address(self):
        called = []
        with unittest.mock.patch.object(T, "default_probe", side_effect=lambda h, p: called.append((h, p)) or ("auth", "login")):
            T.triage({"source": "nmap", "check_id": "3306/tcp", "port": 3306, "hostname": "db.example.test"},
                     {"ip": "8.8.8.8", "port": 3306}, None)
        self.assertEqual(called, [("8.8.8.8", 3306)])

if __name__ == "__main__":
    unittest.main()
