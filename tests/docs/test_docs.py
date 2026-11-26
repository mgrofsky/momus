"""Checks every public documentation page against the tree. Standard library only; reads files, runs nothing.

    python3 -B -m unittest discover -s tests/docs

For each Markdown page (README.md, SECURITY.md, CONTRIBUTING.md, THIRD-PARTY-TOOLS.md, CODE_OF_CONDUCT.md, CHANGELOG.md,
.github/*.md, docs/**/*.md, deploy/*/README.md):
- every relative link and image (Markdown `![...](...)` or HTML `<img src>`) points to a file or folder that exists,
  and every #anchor to a heading of that page;
- every repository path written in a code span or a command exists (placeholders such as <id> match anything);
- every command in a fenced block starts with a known program or a script that exists, and every path in it exists;
- every environment variable name written in a code span is read or set somewhere in the code, Compose files or
  .env.example;
- every test named as "the test that shows it" exists: `path/test_x.py::Class::test_name` (class and function defined
  in that file), or `path/suite.sh` check "LITERAL" for a suite that prints named checks (a shell script, or the
  shim test's driver.py): LITERAL appears in that file.
The checker's own rules are tested on small hostile pages first (CheckerRules), so a check that silently stops
working fails here too.
"""
import ast
import fnmatch
import glob
import os
import re
import shlex
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Paths a page may name that are not in the tree, each with the reason.
NOT_IN_TREE = {
    ".env": "created by the user from .env.example",
    "seed.env": "created by the user for the seeder",
    "seed-zones": "folder the user creates for zone files (mounted by compose.yaml)",
    "secrets": "folder the user creates for Docker secrets (compose.yaml comments)",
    "jobctl-state": "jobctl's default state folder, created when it runs",
    "scanner/config/policy.json": "optional policy file the user creates (scanner/pipeline/settings.py)",
}
TOP = None  # top-level names in the tree, filled lazily

# Programs a command in a fenced block may start with (not files in the tree).
PROGRAMS = {"docker", "python3", "git", "cd", "cp", "mkdir", "cat", "printf", "echo", "ls", "rm", "export", "curl",
            "openssl", "sqlite3", "chmod", "tar", "sha256sum", "shasum", "find", "grep", "head", "tail", "test",
            "bash", "sh", "less", "open", "xdg-open", "sudo", "apt-get", "pip", "aws", "gcloud", "set", "unset",
            "#", "for", "do", "done", "if", "then", "fi", "while", "sleep", "env", "jq", "diff", "mv", "touch"}
SHELL_LANGS = {"sh", "bash", "shell", "console", "zsh"}  # untyped blocks: only lines that start with a known program or path
VAR_PREFIXES = ("MOMUS_", "SCAN_", "SEED_", "AWS_", "JOBCTL_", "ANTHROPIC_", "OPENAI_", "GEMINI_", "GOOGLE_", "HTTP_",
                "HTTPS_", "ALL_PROXY", "NO_PROXY", "SSL_", "REQUESTS_", "CURL_", "BOTO", "AZURE_", "SSLKEYLOGFILE",
                "NETRC", "PYTHON")
TEST_REF = re.compile(r"^([\w./-]+\.py)::(\w+)(?:::(\w+))?$")
SHELL_CHECK = re.compile(r'`([\w./-]+\.(?:sh|py))` check "([^"]+)"')
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")   # links and images alike
IMG_SRC = re.compile(r"""<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
FENCE = re.compile(r"^(\s*)(```+|~~~+)\s*([\w-]*)")


def pages():
    out = []
    for pat in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "THIRD-PARTY-TOOLS.md", "CODE_OF_CONDUCT.md",
                "CHANGELOG.md", ".github/*.md", "docs/**/*.md", "deploy/*/README.md"):
        out += glob.glob(os.path.join(ROOT, pat), recursive=True)
    return sorted(set(os.path.relpath(p, ROOT) for p in out))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def split_blocks(text):
    """(prose, [(lang, block_text)]): prose has fenced blocks blanked out (line numbers kept)."""
    prose, blocks, cur, lang, fence = [], [], None, "", None
    for line in text.split("\n"):
        m = FENCE.match(line)
        if cur is None and m:
            cur, lang, fence = [], m.group(3).lower(), m.group(2)
            prose.append("")
        elif cur is not None and line.strip().startswith(fence[0] * len(fence)) and line.strip().strip(fence[0]) == "":
            blocks.append((lang, "\n".join(cur)))
            cur = None
            prose.append("")
        elif cur is not None:
            cur.append(line)
            prose.append("")
        else:
            prose.append(line)
    # indented code blocks (four spaces, after a blank line, outside a list) are untyped blocks too
    out, ind, prev, in_list = [], None, "", False
    for line in prose:
        if line.lstrip().startswith(("- ", "* ")) or re.match(r"^\s*\d+\. ", line):
            in_list = True
        elif not line.strip() and not prev.strip():
            in_list = False
        if ind is None and line.startswith("    ") and not prev.strip() and not in_list:
            ind = [line[4:]]
            out.append("")
        elif ind is not None and (line.startswith("    ") or not line.strip()):
            ind.append(line[4:])
            out.append("")
        else:
            if ind is not None:
                blocks.append(("", "\n".join(ind)))
                ind = None
            out.append(line)
        prev = line
    if ind is not None:
        blocks.append(("", "\n".join(ind)))
    return "\n".join(out), blocks


def code_spans(prose):
    spans = []
    for m in re.finditer(r"(`+)(.+?)\1", prose, flags=re.S):
        spans.append(m.group(2).strip())
    return spans


def slug(heading):
    h = re.sub(r"[`*]", "", heading.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(text):
    prose, _ = split_blocks(text)
    seen, out = {}, set()
    for line in prose.split("\n"):
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            out.add(s if n == 0 else f"{s}-{n}")
            seen[s] = n + 1
    return out


def top_names():
    global TOP
    if TOP is None:
        TOP = set(os.listdir(ROOT)) - {".git"}
    return TOP


def looks_like_repo_path(s):
    if not s or " " in s or s.startswith(("/", "http", "-", "$", "~")) or "://" in s:
        return False
    first = s.split("/")[0]
    return first in top_names() or first in NOT_IN_TREE or (
        "/" in s and first in {"docs", "scanner", "brain", "seeder", "deploy", "tests", "demo"})


def path_exists(s):
    s = s.rstrip("/").split("#")[0].split(":")[0] if "::" not in s else s.split("::")[0]
    if s in NOT_IN_TREE or any(s == k or s.startswith(k + "/") for k in NOT_IN_TREE):
        return True
    pat = re.sub(r"<[^>]*>", "*", s)
    if any(ch in pat for ch in "*?["):
        return bool(glob.glob(os.path.join(ROOT, pat)))
    return os.path.exists(os.path.join(ROOT, pat))


def corpus():
    """Every non-Markdown text file in the tree (code, Compose, Dockerfiles, .env.example), for variable names."""
    buf = []
    for dirpath, dirnames, files in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules")]
        for f in files:
            if f.endswith((".md", ".png", ".svg", ".min.js", ".sqlite")):
                continue
            try:
                with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                    buf.append(fh.read())
            except (UnicodeDecodeError, OSError):
                pass
    return "\n".join(buf)


def test_ref_errors(ref):
    m = TEST_REF.match(ref)
    if not m:
        return []
    path, a, b = m.groups()
    full = os.path.join(ROOT, path)
    if not os.path.isfile(full):
        return [f"test file does not exist: {ref}"]
    tree = ast.parse(read(path))
    if b is None:
        names = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef))}
        return [] if a in names else [f"no test or class {a} in {path}"]
    for n in tree.body:
        if isinstance(n, ast.ClassDef) and n.name == a:
            if any(isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == b for f in n.body):
                return []
            return [f"class {a} in {path} has no {b}"]
    return [f"no class {a} in {path}"]


def command_errors(lang, block):
    errs = []
    if lang not in SHELL_LANGS and lang not in ("", "text"):
        return errs
    strict = lang in SHELL_LANGS
    text = re.sub(r"\\\n", " ", block)
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("$ "):
            line = line[2:]
        if not re.match(r"^[\w./$-]", line) or line.startswith(("{", "[", '"')):
            continue  # output or JSON shown in the block, not a command
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        for part in " ".join(shlex.quote(w) for w in words).split(" && "):
            ws = shlex.split(part) if part else []
            while ws and re.match(r"^\w+=", ws[0]):
                ws = ws[1:]
            if not ws:
                continue
            prog = ws[0]
            if prog in ("|", "(", ")"):
                continue
            if not strict and prog not in PROGRAMS and not looks_like_repo_path(prog):
                continue  # prose or output in an untyped block
            if prog not in PROGRAMS and not (looks_like_repo_path(prog) and path_exists(prog)):
                if "/" in prog or prog.endswith((".sh", ".py")):
                    errs.append(f"command does not exist: {prog}")
                else:
                    errs.append(f"unknown program (add it to PROGRAMS if it is a real program): {prog}")
            for w in ws[1:]:
                w2 = w.split("=", 1)[1] if w.startswith("--") and "=" in w else w
                if looks_like_repo_path(w2) and not path_exists(w2) and ":" not in w2:
                    errs.append(f"path in command does not exist: {w2}")
            if prog == "python3" and "-m" in ws:
                mod = ws[ws.index("-m") + 1] if ws.index("-m") + 1 < len(ws) else ""
                if "." in mod and not any(os.path.exists(os.path.join(ROOT, d, *mod.split("."))) or
                                          os.path.exists(os.path.join(ROOT, d, *mod.split(".")) + ".py")
                                          for d in ("", "brain", "scanner", "seeder")):
                    errs.append(f"python module does not exist: {mod}")
    return errs


def page_errors(rel, text, known_vars=None):
    errs = []
    prose, blocks = split_blocks(text)
    here = os.path.dirname(rel)
    for target in [m.group(1) for m in LINK.finditer(prose)] + IMG_SRC.findall(prose):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path, _, anchor = target.partition("#")
        dest = os.path.normpath(os.path.join(here, path)) if path else rel
        if path and not path_exists(dest):
            errs.append(f"{rel}: link to a missing file: {target}")
        elif anchor and (not path or (dest.endswith(".md") and os.path.isfile(os.path.join(ROOT, dest)))):
            if anchor not in anchors(read(dest) if path else text):
                errs.append(f"{rel}: link to a missing heading: {target}")
    for span in code_spans(prose):
        if TEST_REF.match(span):
            errs += [f"{rel}: {e}" for e in test_ref_errors(span)]
        elif looks_like_repo_path(span) and not path_exists(span):
            errs.append(f"{rel}: path does not exist: {span}")
        elif known_vars is not None and re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", span) and span.startswith(VAR_PREFIXES):
            if span not in known_vars:
                errs.append(f"{rel}: variable is not read or set anywhere in the code: {span}")
    for m in SHELL_CHECK.finditer(prose):
        script, literal = m.groups()
        if not os.path.isfile(os.path.join(ROOT, script)) or literal not in read(script):
            errs.append(f'{rel}: no check "{literal}" in {script}')
    for lang, block in blocks:
        if lang == "mermaid":
            errs.append(f"{rel}: diagrams are not written in Markdown")
        errs += [f"{rel}: {e}" for e in command_errors(lang, block)]
    return errs


class CheckerRules(unittest.TestCase):
    """The checker finds each kind of mistake (so a rule that stops working fails here)."""

    def errs(self, text, known=frozenset({"MOMUS_LAB"})):
        return page_errors("docs/example.md", text, set(known))

    def test_a_broken_link_is_found(self):
        self.assertTrue(self.errs("See [the page](no-such-page.md)."))
        self.assertFalse(self.errs("See [the page](../README.md)."))

    def test_a_missing_image_is_found(self):
        self.assertTrue(self.errs("![diagram](diagrams/no-such-image.png)"))
        self.assertTrue(self.errs('<img src="diagrams/no-such-image.svg" alt="x">'))
        self.assertFalse(self.errs("![diagram](diagrams/momus-dataflow.png)"))
        self.assertFalse(self.errs('<img alt="x" src="diagrams/momus-dataflow.svg">'))

    def test_a_broken_anchor_is_found(self):
        self.assertTrue(self.errs("# Title\nSee [below](#nowhere)."))
        self.assertFalse(self.errs("# Title\n## Below here\nSee [below](#below-here)."))

    def test_a_missing_path_is_found(self):
        self.assertTrue(self.errs("Read `scanner/no_such_file.py`."))
        self.assertFalse(self.errs("Read `scanner/runner.py` and `docs/diagrams/`."))

    def test_a_missing_command_is_found(self):
        self.assertTrue(self.errs("```sh\ntests/e2e/no_such_script.sh\n```"))
        self.assertTrue(self.errs("```sh\nfrobnicate --all\n```"))
        self.assertTrue(self.errs("```\npython3 -B scanner/nothing_here.py\n```"))
        self.assertFalse(self.errs("```\nYou are a model. Rules:\n1. Read only.\n```"))
        self.assertFalse(self.errs("```sh\ntests/e2e/run_demo.sh\n```"))
        self.assertTrue(self.errs("Run it:\n\n    scanner/tests/no_such_runner.sh\n"))

    def test_a_fake_test_name_is_found(self):
        self.assertTrue(self.errs("Shown by `scanner/pipeline/test_scope.py::NoSuchClass::test_x`."))
        self.assertTrue(self.errs("Shown by `brain/tests/test_auth.py::test_no_such_test_anywhere`."))
        self.assertTrue(self.errs('Shown by `tests/e2e/run_demo.sh` check "no such check text at all".'))
        self.assertFalse(self.errs('Shown by `tests/e2e/run_demo.sh` check "the lab stack starts".'))

    def test_an_unknown_variable_is_found(self):
        self.assertTrue(self.errs("Set `MOMUS_NO_SUCH_SETTING`."))
        self.assertFalse(self.errs("Set `MOMUS_LAB`."))

    def test_a_mermaid_block_is_found(self):
        self.assertTrue(self.errs("```mermaid\ngraph TD\n```"))


class Pages(unittest.TestCase):
    def test_the_pages_exist(self):
        for p in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "THIRD-PARTY-TOOLS.md", "CODE_OF_CONDUCT.md",
                  "CHANGELOG.md", ".github/pull_request_template.md", "docs/architecture.md",
                  "docs/configuration.md", "docs/threat-model.md"):
            self.assertIn(p, pages())

    def test_every_link_path_command_variable_and_test_name_exists(self):
        names = set(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", corpus()))
        errs = []
        for rel in pages():
            errs += page_errors(rel, read(rel), names)
        self.assertEqual(errs, [], "\n" + "\n".join(errs))


if __name__ == "__main__":
    unittest.main()
