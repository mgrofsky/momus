"""docs/configuration.md and .env.example name every setting the code reads, and nothing else. Standard library only.

    python3 -B -m unittest discover -s tests/docs

Variables read by the code are found by reading the source, never by importing it:
- Python (brain, scanner, seeder; test files left out): a MOMUS_, SCAN_ or SEED_ name given as a string constant to
  .get(), .pop(), .setdefault(), os.getenv() or the seeder's switch(), or used as a subscript (environ["NAME"]);
- shell (scanner/entrypoint.sh, scanner/recon.sh, scanner/update-templates.sh): $NAME, ${NAME...} and the names in the
  entrypoint's allow-list loop;
- Compose files: keys under environment:.
The test fails when a name read by the code is neither a row of a table in docs/configuration.md nor named in
.env.example (unless it is in NOT_SETTINGS below with its reason), when the page has a row for a name the code does not
read, and when an entry of NOT_SETTINGS is no longer read anywhere (so the list cannot go stale).
"""
import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NAME = re.compile(r"^(?:MOMUS|SCAN|SEED)_[A-Z0-9_]+$")

# Read by the code, but not settings a user gives. Each needs its reason; each must still be read somewhere.
NOT_SETTINGS = {
    # test harnesses only
    "MOMUS_ANALYST_MOCK_RECORD": "lab mode only: the end-to-end test's record file for the mock provider",
    # set by the scanner's runner for the pipeline steps it starts, from the job
    "SCAN_EVIDENCE": "the runner passes the job's evidence level to each step",
    "SCAN_NUCLEI_TEMPLATES": "the runner passes the template folder to recon.sh",
    "SCAN_SEED_DIR": "the runner passes the seed folder to recon.sh",
    "SCAN_CHECK_PROFILE": "recon.sh run by hand only; in the container the job's profile file wins",
    "SCAN_RATE_PROFILE": "recon.sh run by hand only; in the container the job's profile file wins",
    # read, but the entrypoint's clean environment never passes them, so they always take their default
    "SCAN_SEED_SCOPE_DIR": "not passed by scanner/entrypoint.sh; always /srv/seed-scope",
    "SCAN_USER_AGENT": "not passed by scanner/entrypoint.sh; always the built-in user agent",
    # passed by the entrypoint's allow-list, but nothing reads it
    "SCAN_EXIT_WHEN_IDLE": "on the allow-list in scanner/entrypoint.sh; no code reads it",
    # read only to warn that it has no effect
    "MOMUS_LOGIN_WINDOW_MINUTES": "not a setting; the brain logs that it is ignored",
}
# Names that look like variables in the source but are not environment variables at all.
NOT_VARIABLES = {
    "SCAN_TYPES", "SCAN_PORTS", "SEED_DIR", "SEED_SCOPE_FILE", "SEED_SCOPE_SCHEMA", "MOMUS_EGRESS",
}
PY_ROOTS = ("brain/app", "brain/run.py", "brain/tools", "scanner/runner.py", "scanner/jobctl.py", "scanner/pipeline",
            "seeder/seed_dns.py")
SHELL = ("scanner/entrypoint.sh", "scanner/recon.sh", "scanner/update-templates.sh")
COMPOSE = ("compose.yaml", "compose.lab.yaml")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def py_files():
    for r in PY_ROOTS:
        full = os.path.join(ROOT, r)
        if os.path.isfile(full):
            yield r
            continue
        for dirpath, dirnames, files in os.walk(full):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for f in files:
                if f.endswith(".py") and not f.startswith("test_"):
                    yield os.path.relpath(os.path.join(dirpath, f), ROOT)


def names_in_python(source):
    found = set()
    for node in ast.walk(ast.parse(source)):
        arg = None
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            f = node.func
            fname = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if fname in ("get", "pop", "setdefault", "getenv", "switch"):
                arg = node.args[0].value
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            arg = node.slice.value
        if isinstance(arg, str) and NAME.match(arg):
            found.add(arg)
    return found


def names_in_shell(source):
    found = set(re.findall(r"\$\{?!?((?:MOMUS|SCAN|SEED)_[A-Z0-9_]+)", source))
    for loop in re.findall(r"for v in ([^;]+); do", source):
        found |= {w for w in loop.split() if NAME.match(w)}
    return found


def names_in_compose(source):
    return set(re.findall(r"^\s+((?:MOMUS|SCAN|SEED)_[A-Z0-9_]+):", source, flags=re.M))


def read_by_code():
    names = set()
    for rel in py_files():
        names |= names_in_python(read(rel))
    for rel in SHELL:
        names |= names_in_shell(read(rel))
    for rel in COMPOSE:
        names |= names_in_compose(read(rel))
    return names - NOT_VARIABLES


def page_rows(text):
    return set(re.findall(r"^\|\s*`((?:MOMUS|SCAN|SEED)_[A-Z0-9_]+)`", text, flags=re.M))


def env_example_names(text):
    return set(re.findall(r"\b((?:MOMUS|SCAN|SEED)_[A-Z0-9_]+)\b", text))


class Extraction(unittest.TestCase):
    """The readers find every reading style the code uses (so a style that stops being found fails here)."""

    def test_python_reading_styles(self):
        src = ('import os\nos.environ.get("MOMUS_A")\nenv.get("SCAN_B", "1")\nos.getenv("SEED_C")\n'
               'os.environ["MOMUS_D"]\nswitch("SEED_E")\nd.get("lab_cidr")\nprint("MOMUS_NOT_READ")\n')
        self.assertEqual(names_in_python(src), {"MOMUS_A", "SCAN_B", "SEED_C", "MOMUS_D", "SEED_E"})

    def test_shell_reading_styles(self):
        src = 'x=$SCAN_A\ny=${SCAN_B:-1}\nz="${!SCAN_C}"\nfor v in SCAN_D TZ SCAN_E; do\n'
        self.assertEqual(names_in_shell(src), {"SCAN_A", "SCAN_B", "SCAN_C", "SCAN_D", "SCAN_E"})

    def test_page_rows(self):
        self.assertEqual(page_rows("| `MOMUS_A` | 1 |\n| Name |\nText `MOMUS_B`.\n"), {"MOMUS_A"})


class Configuration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.read = read_by_code()
        cls.rows = page_rows(read("docs/configuration.md"))
        cls.example = env_example_names(read(".env.example"))
        cls.settings = cls.read - set(NOT_SETTINGS)

    def test_the_reader_finds_the_known_settings(self):
        for n in ("MOMUS_ALLOWED_ORIGINS", "MOMUS_ANALYST_PROVIDER", "SCAN_JOB_MAX_AGE_HOURS", "SCAN_LAB", "SEED_AXFR",
                  "SEED_ROUTE53"):
            self.assertIn(n, self.read)

    def test_every_setting_the_code_reads_is_on_the_page(self):
        self.assertEqual(sorted(self.settings - self.rows), [],
                         "read by the code but missing from docs/configuration.md")

    def test_every_setting_the_code_reads_is_named_in_env_example(self):
        self.assertEqual(sorted(self.settings - self.example), [], "read by the code but missing from .env.example")

    def test_the_page_names_only_settings_the_code_reads(self):
        self.assertEqual(sorted(self.rows - self.settings), [],
                         "on docs/configuration.md but not read by the code (or listed as not a setting)")

    def test_env_example_sets_only_settings_the_code_reads(self):
        assigned = set(re.findall(r"^((?:MOMUS|SCAN|SEED)_[A-Z0-9_]+)=", read(".env.example"), flags=re.M))
        self.assertEqual(sorted(assigned - self.settings), [])

    def test_the_list_of_names_that_are_not_settings_is_not_stale(self):
        self.assertEqual(sorted(set(NOT_SETTINGS) - self.read), [], "listed in NOT_SETTINGS but read nowhere")
        self.assertEqual(sorted(set(NOT_SETTINGS) & self.rows), [], "listed as not a setting but on the page")


if __name__ == "__main__":
    unittest.main()
