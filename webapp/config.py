from __future__ import annotations

import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppSettings:
    project_root: Path
    data_dir: Path
    paths_file: Path
    oneforall_dir: Path
    oneforall_python: Path
    nuclei_binary: str
    username: str
    password: str
    session_secret: str
    default_host: str
    default_port: int
    mysql_host: str
    mysql_port: int
    mysql_user: str
    mysql_password: str
    mysql_database: str
    cookie_secure: bool
    forwarded_allow_ips: str
    login_max_attempts: int
    login_window_seconds: int
    login_block_seconds: int

    @classmethod
    def from_env(cls) -> "AppSettings":
        project_root = Path(__file__).resolve().parent.parent
        data_dir = Path(os.getenv("WEBAPP_DATA_DIR", project_root / "data")).expanduser().resolve()
        oneforall_dir = Path(
            os.getenv(
                "ONEFORALL_DIR",
                "D:/Tools/OneForAll" if os.name == "nt" else "/opt/OneForAll",
            )
        ).expanduser()
        default_python = (
            oneforall_dir / ".venv" / "Scripts" / "python.exe"
            if os.name == "nt"
            else oneforall_dir / ".venv" / "bin" / "python"
        )
        password = os.getenv("WEBAPP_PASSWORD", "change-me")
        return cls(
            project_root=project_root,
            data_dir=data_dir,
            paths_file=Path(os.getenv("WEBAPP_PATHS_FILE", project_root / "paths.txt")).expanduser().resolve(),
            oneforall_dir=oneforall_dir,
            oneforall_python=Path(os.getenv("ONEFORALL_PYTHON", default_python)).expanduser(),
            nuclei_binary=os.getenv("NUCLEI_BIN", "nuclei"),
            username=os.getenv("WEBAPP_USERNAME", "admin"),
            password=password,
            session_secret=os.getenv("WEBAPP_SESSION_SECRET", secrets.token_urlsafe(32)),
            default_host=os.getenv("WEBAPP_HOST", "127.0.0.1"),
            default_port=int(os.getenv("WEBAPP_PORT", "8000")),
            mysql_host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            mysql_port=int(os.getenv("MYSQL_PORT", "3306")),
            mysql_user=os.getenv("MYSQL_USER", "webasset"),
            mysql_password=os.getenv("MYSQL_PASSWORD", ""),
            mysql_database=os.getenv("MYSQL_DATABASE", "web_asset_checker"),
            cookie_secure=os.getenv("WEBAPP_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"},
            forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
            login_max_attempts=max(1, int(os.getenv("WEBAPP_LOGIN_MAX_ATTEMPTS", "5"))),
            login_window_seconds=max(1, int(os.getenv("WEBAPP_LOGIN_WINDOW_SECONDS", "300"))),
            login_block_seconds=max(1, int(os.getenv("WEBAPP_LOGIN_BLOCK_SECONDS", "900"))),
        )

    @property
    def uses_default_password(self) -> bool:
        return self.password.lower() in {"change-me", "admin", "password", "123456"}

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "tasks").mkdir(parents=True, exist_ok=True)

    def tool_status(self) -> dict[str, object]:
        oneforall_script = self.oneforall_dir / "oneforall.py"
        nuclei_path = shutil.which(self.nuclei_binary)
        return {
            "oneforall": bool(oneforall_script.is_file() and self.oneforall_python.is_file()),
            "oneforall_dir": str(self.oneforall_dir),
            "oneforall_python": str(self.oneforall_python),
            "nuclei": bool(nuclei_path),
            "nuclei_path": nuclei_path or self.nuclei_binary,
            "paths_file": str(self.paths_file),
            "data_dir": str(self.data_dir),
            "mysql_host": f"{self.mysql_host}:{self.mysql_port}",
            "mysql_database": self.mysql_database,
            "mysql_user": self.mysql_user,
        }
