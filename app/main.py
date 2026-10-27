"""启动入口: python3.10 -m app.main 或 ./run.sh"""
from __future__ import annotations

import uvicorn

from .config import SETTINGS


def main() -> None:
    uvicorn.run(
        "app.api:app",
        host=SETTINGS.host,
        port=SETTINGS.port,
        log_level="info",
        reload=False,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    main()
