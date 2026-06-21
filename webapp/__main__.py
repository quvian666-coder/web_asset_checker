from __future__ import annotations

import argparse

import uvicorn

from .config import AppSettings


def main() -> None:
    defaults = AppSettings.from_env()
    parser = argparse.ArgumentParser(description="Web Asset Console")
    parser.add_argument("--host", default=defaults.default_host)
    parser.add_argument("--port", type=int, default=defaults.default_port)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    uvicorn.run("webapp.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
