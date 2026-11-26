"""Start the brain: one uvicorn process, one worker (the scheduler and the bootstrap token live in this process)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.llm import envguard  # noqa: E402  (standard library only)

# before anything else is imported: the variables the model SDKs would read that no constructor argument overrides
envguard.scrub_at_start()

import uvicorn  # noqa: E402

from app.config import from_env, listen_port  # noqa: E402
from app.web import StartupRefused, create_app  # noqa: E402


def main():
    try:
        port = listen_port()
    except ValueError as e:
        print(f"brain: {e}", flush=True)
        sys.exit(2)
    settings = from_env()
    try:
        app = create_app(settings)
    except StartupRefused as e:
        print(f"brain: {e}", flush=True)
        sys.exit(2)
    uvicorn.run(app, host=os.environ.get("MOMUS_LISTEN_HOST", "0.0.0.0"), port=port,
                workers=1, proxy_headers=False, server_header=False, date_header=True, access_log=False, log_level="info")


if __name__ == "__main__":
    main()
