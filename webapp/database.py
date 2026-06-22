from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from .findings import FindingReviewUpdate, finding_fingerprint, normalize_endpoint


DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def now_sql() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key, value in result.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat(sep=" ", timespec="seconds")
    return result


class Database:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        password: str,
        database: str,
    ) -> None:
        if not DATABASE_NAME_RE.fullmatch(database):
            raise ValueError("MYSQL_DATABASE 只能包含字母、数字和下划线")
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database

    def connect(self, *, include_database: bool = True) -> pymysql.Connection:
        return pymysql.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            database=self.database if include_database else None,
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=True,
            connect_timeout=8,
            read_timeout=30,
            write_timeout=30,
        )

    def initialize(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INT PRIMARY KEY,
                applied_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id VARCHAR(32) PRIMARY KEY,
                name VARCHAR(80) NOT NULL,
                status VARCHAR(20) NOT NULL,
                stage VARCHAR(200) NOT NULL DEFAULT '等待执行',
                progress INT NOT NULL DEFAULT 0,
                config_json LONGTEXT NOT NULL,
                counts_json LONGTEXT NOT NULL,
                error TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                started_at DATETIME NULL,
                finished_at DATETIME NULL,
                INDEX idx_tasks_status(status),
                INDEX idx_tasks_created(created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS task_events (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                task_id VARCHAR(32) NOT NULL,
                timestamp DATETIME NOT NULL,
                level VARCHAR(20) NOT NULL,
                message TEXT NOT NULL,
                INDEX idx_events_task_id(task_id, id),
                CONSTRAINT fk_events_task FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS assets (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                task_id VARCHAR(32) NOT NULL,
                root_domain VARCHAR(253) NOT NULL,
                subdomain VARCHAR(253) NOT NULL,
                url TEXT NOT NULL,
                ip TEXT NOT NULL,
                port VARCHAR(20) NOT NULL DEFAULT '',
                status_code VARCHAR(20) NOT NULL DEFAULT '',
                title VARCHAR(500) NOT NULL DEFAULT '',
                banner TEXT NOT NULL,
                server VARCHAR(500) NOT NULL DEFAULT '',
                cdn VARCHAR(100) NOT NULL DEFAULT '',
                source VARCHAR(500) NOT NULL DEFAULT '',
                INDEX idx_assets_task(task_id),
                INDEX idx_assets_root(root_domain),
                INDEX idx_assets_subdomain(subdomain),
                CONSTRAINT fk_assets_task FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                task_id VARCHAR(32) NOT NULL,
                root_domain VARCHAR(253) NOT NULL,
                subdomain VARCHAR(253) NOT NULL,
                base_url TEXT NOT NULL,
                endpoint_url TEXT NOT NULL,
                `function` VARCHAR(200) NOT NULL,
                category VARCHAR(80) NOT NULL,
                status_code VARCHAR(20) NOT NULL DEFAULT '',
                access_state VARCHAR(40) NOT NULL,
                confidence VARCHAR(20) NOT NULL,
                priority VARCHAR(10) NOT NULL,
                title VARCHAR(500) NOT NULL DEFAULT '',
                server VARCHAR(500) NOT NULL DEFAULT '',
                x_powered_by VARCHAR(500) NOT NULL DEFAULT '',
                content_type VARCHAR(500) NOT NULL DEFAULT '',
                response_length BIGINT NOT NULL DEFAULT 0,
                redirect_url TEXT NOT NULL,
                similarity DOUBLE NOT NULL DEFAULT 0,
                next_check TEXT NOT NULL,
                scan_time VARCHAR(40) NOT NULL,
                INDEX idx_findings_task(task_id),
                INDEX idx_findings_priority(priority),
                INDEX idx_findings_category(category),
                CONSTRAINT fk_findings_task FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
        ]
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                for statement in statements:
                    cursor.execute(statement)
                self._apply_migrations(cursor)
                cursor.execute(
                    """
                    UPDATE tasks SET status='FAILED', stage='服务重启导致任务中断',
                        error='任务未正常结束', finished_at=%s
                    WHERE status IN ('QUEUED','RUNNING')
                    """,
                    (now_sql(),),
                )
        finally:
            connection.close()

    def _apply_migrations(self, cursor: pymysql.cursors.DictCursor) -> None:
        cursor.execute("SELECT version FROM schema_migrations")
        applied = {int(row["version"]) for row in cursor.fetchall()}
        if 1 not in applied:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS finding_cases (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    fingerprint CHAR(64) NOT NULL UNIQUE,
                    root_domain VARCHAR(253) NOT NULL,
                    subdomain VARCHAR(253) NOT NULL,
                    endpoint_url TEXT NOT NULL,
                    `function` VARCHAR(200) NOT NULL,
                    category VARCHAR(80) NOT NULL,
                    review_status VARCHAR(24) NOT NULL DEFAULT 'PENDING_RETEST',
                    assignee VARCHAR(80) NOT NULL DEFAULT '',
                    notes TEXT NOT NULL,
                    tags_json LONGTEXT NOT NULL,
                    evidence_summary TEXT NOT NULL,
                    first_seen_at DATETIME NOT NULL,
                    last_seen_at DATETIME NOT NULL,
                    last_retested_at DATETIME NULL,
                    updated_at DATETIME NOT NULL,
                    INDEX idx_case_status(review_status),
                    INDEX idx_case_assignee(assignee),
                    INDEX idx_case_last_seen(last_seen_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cursor.execute(
                """
                SELECT COUNT(*) AS count FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=%s AND TABLE_NAME='findings' AND COLUMN_NAME='case_id'
                """,
                (self.database,),
            )
            if int(cursor.fetchone()["count"]) == 0:
                cursor.execute("ALTER TABLE findings ADD COLUMN case_id BIGINT NULL AFTER task_id")
                cursor.execute("ALTER TABLE findings ADD INDEX idx_findings_case(case_id)")
                cursor.execute(
                    """
                    ALTER TABLE findings ADD CONSTRAINT fk_findings_case
                    FOREIGN KEY(case_id) REFERENCES finding_cases(id) ON DELETE SET NULL
                    """
                )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS finding_case_events (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    case_id BIGINT NOT NULL,
                    actor VARCHAR(80) NOT NULL,
                    old_status VARCHAR(24) NOT NULL,
                    new_status VARCHAR(24) NOT NULL,
                    assignee VARCHAR(80) NOT NULL DEFAULT '',
                    notes TEXT NOT NULL,
                    tags_json LONGTEXT NOT NULL,
                    evidence_summary TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    INDEX idx_case_events(case_id, id),
                    CONSTRAINT fk_case_events_case FOREIGN KEY(case_id)
                        REFERENCES finding_cases(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            self._backfill_finding_cases(cursor)
            cursor.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(%s,%s)",
                (1, now_sql()),
            )

        if 2 not in applied:
            cursor.execute("ALTER TABLE assets MODIFY COLUMN ip TEXT NOT NULL")
            cursor.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(%s,%s)",
                (2, now_sql()),
            )

    @staticmethod
    def _seen_at(value: Any) -> str:
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        try:
            return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return now_sql()

    def _upsert_finding_case(self, cursor: pymysql.cursors.DictCursor, item: dict[str, Any]) -> int:
        endpoint_url = normalize_endpoint(item["endpoint_url"])
        fingerprint = finding_fingerprint(endpoint_url, item["category"])
        seen_at = self._seen_at(item.get("scan_time"))
        cursor.execute(
            """
            INSERT INTO finding_cases(
                fingerprint,root_domain,subdomain,endpoint_url,`function`,category,
                review_status,assignee,notes,tags_json,evidence_summary,
                first_seen_at,last_seen_at,last_retested_at,updated_at
            ) VALUES(%s,%s,%s,%s,%s,%s,'PENDING_RETEST','','','[]','',%s,%s,NULL,%s)
            ON DUPLICATE KEY UPDATE
                root_domain=VALUES(root_domain),subdomain=VALUES(subdomain),
                endpoint_url=VALUES(endpoint_url),`function`=VALUES(`function`),
                category=VALUES(category),last_seen_at=GREATEST(last_seen_at,VALUES(last_seen_at)),
                updated_at=VALUES(updated_at)
            """,
            (
                fingerprint,
                item.get("root_domain", ""),
                item.get("subdomain", ""),
                endpoint_url,
                item.get("function", ""),
                item.get("category", ""),
                seen_at,
                seen_at,
                now_sql(),
            ),
        )
        cursor.execute("SELECT id FROM finding_cases WHERE fingerprint=%s", (fingerprint,))
        return int(cursor.fetchone()["id"])

    def _backfill_finding_cases(self, cursor: pymysql.cursors.DictCursor) -> None:
        cursor.execute("SELECT * FROM findings WHERE case_id IS NULL ORDER BY id ASC")
        for item in cursor.fetchall():
            case_id = self._upsert_finding_case(cursor, item)
            cursor.execute("UPDATE findings SET case_id=%s WHERE id=%s", (case_id, item["id"]))

    def health(self) -> bool:
        try:
            connection = self.connect()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 AS ok")
                    return cursor.fetchone()["ok"] == 1
            finally:
                connection.close()
        except pymysql.MySQLError:
            return False

    def create_task(self, task_id: str, name: str, config: dict[str, Any]) -> None:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO tasks(id,name,status,stage,progress,config_json,counts_json,error,created_at)
                    VALUES(%s,%s,'QUEUED','等待执行',0,%s,'{}','',%s)
                    """,
                    (task_id, name, json.dumps(config, ensure_ascii=False), now_sql()),
                )
        finally:
            connection.close()

    def update_task(self, task_id: str, **fields: Any) -> None:
        allowed = {
            "status",
            "stage",
            "progress",
            "counts_json",
            "error",
            "started_at",
            "finished_at",
        }
        values = {key: value for key, value in fields.items() if key in allowed}
        if not values:
            return
        assignments = ", ".join(f"{key}=%s" for key in values)
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"UPDATE tasks SET {assignments} WHERE id=%s",
                    (*values.values(), task_id),
                )
        finally:
            connection.close()

    def append_event(self, task_id: str, level: str, message: str) -> int:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO task_events(task_id,timestamp,level,message) VALUES(%s,%s,%s,%s)",
                    (task_id, now_sql(), level.upper(), message[:2000]),
                )
                return int(cursor.lastrowid)
        finally:
            connection.close()

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM tasks WHERE id=%s", (task_id,))
                row = cursor.fetchone()
        finally:
            connection.close()
        return self._task_dict(row) if row else None

    def list_tasks(self, limit: int = 50) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT %s", (limit,))
                rows = cursor.fetchall()
        finally:
            connection.close()
        return [self._task_dict(row) for row in rows]

    def get_events(self, task_id: str, after_id: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT * FROM task_events WHERE task_id=%s AND id>%s
                    ORDER BY id ASC LIMIT %s
                    """,
                    (task_id, after_id, limit),
                )
                rows = cursor.fetchall()
        finally:
            connection.close()
        return [serialize_row(row) for row in rows]

    def replace_assets(self, task_id: str, assets: list[dict[str, Any]]) -> None:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM assets WHERE task_id=%s", (task_id,))
                if assets:
                    cursor.executemany(
                        """
                        INSERT INTO assets(
                            task_id,root_domain,subdomain,url,ip,port,status_code,title,banner,server,cdn,source
                        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        [
                            (
                                task_id,
                                item.get("root_domain", ""),
                                item.get("subdomain", ""),
                                item.get("url", ""),
                                item.get("ip", ""),
                                str(item.get("port", "")),
                                str(item.get("status_code", "")),
                                item.get("title", ""),
                                item.get("banner", ""),
                                item.get("server", ""),
                                str(item.get("cdn", "")),
                                item.get("source", ""),
                            )
                            for item in assets
                        ],
                    )
        finally:
            connection.close()

    def update_asset_probe(
        self,
        task_id: str,
        url: str,
        *,
        status_code: int | None,
        title: str,
        server: str,
    ) -> None:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE assets SET status_code=%s,title=%s,server=%s
                    WHERE task_id=%s AND url=%s
                    """,
                    (str(status_code or ""), title, server, task_id, url),
                )
        finally:
            connection.close()

    def replace_findings(self, task_id: str, findings: list[dict[str, Any]]) -> None:
        connection = self.connect()
        try:
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM findings WHERE task_id=%s", (task_id,))
                for item in findings:
                    case_id = self._upsert_finding_case(cursor, item)
                    cursor.execute(
                        """
                        INSERT INTO findings(
                            task_id,case_id,root_domain,subdomain,base_url,endpoint_url,`function`,category,
                            status_code,access_state,confidence,priority,title,server,x_powered_by,
                            content_type,response_length,redirect_url,similarity,next_check,scan_time
                        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            task_id,
                            case_id,
                            item["root_domain"],
                            item["subdomain"],
                            item["base_url"],
                            normalize_endpoint(item["endpoint_url"]),
                            item["function"],
                            item["category"],
                            str(item.get("status_code", "")),
                            item["access_state"],
                            item["confidence"],
                            item["priority"],
                            item.get("title", ""),
                            item.get("server", ""),
                            item.get("x_powered_by", ""),
                            item.get("content_type", ""),
                            int(item.get("response_length", 0)),
                            item.get("redirect_url", ""),
                            float(item.get("similarity", 0)),
                            item["next_check"],
                            item["scan_time"],
                        ),
                    )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_assets(self, task_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        query = "SELECT * FROM assets"
        params: list[Any] = []
        if task_id:
            query += " WHERE task_id=%s"
            params.append(task_id)
        query += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return [serialize_row(row) for row in cursor.fetchall()]
        finally:
            connection.close()

    def list_findings(self, task_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        query = """
            SELECT f.*,c.review_status,c.assignee,c.notes,c.tags_json,c.evidence_summary,
                   c.first_seen_at,c.last_seen_at,c.last_retested_at
            FROM findings f LEFT JOIN finding_cases c ON c.id=f.case_id
        """
        params: list[Any] = []
        if task_id:
            query += " WHERE f.task_id=%s"
            params.append(task_id)
        query += " ORDER BY FIELD(f.priority,'P1','P2','P3'), f.id DESC LIMIT %s"
        params.append(limit)
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                rows = [serialize_row(row) for row in cursor.fetchall()]
                for row in rows:
                    row["tags"] = json.loads(row.pop("tags_json") or "[]") if "tags_json" in row else []
                return rows
        finally:
            connection.close()

    @staticmethod
    def _case_select() -> str:
        return """
            SELECT c.*,f.access_state,f.confidence,f.priority,f.title,f.status_code,
                   f.next_check,f.task_id
            FROM finding_cases c
            LEFT JOIN findings f ON f.id=(
                SELECT f2.id FROM findings f2 WHERE f2.case_id=c.id ORDER BY f2.id DESC LIMIT 1
            )
        """

    @staticmethod
    def _case_dict(row: dict[str, Any]) -> dict[str, Any]:
        data = serialize_row(row)
        data["tags"] = json.loads(data.pop("tags_json") or "[]")
        return data

    def list_finding_cases(self, task_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        query = self._case_select()
        params: list[Any] = []
        if task_id:
            query += " WHERE EXISTS(SELECT 1 FROM findings ft WHERE ft.case_id=c.id AND ft.task_id=%s)"
            params.append(task_id)
        query += " ORDER BY FIELD(f.priority,'P1','P2','P3'),c.last_seen_at DESC LIMIT %s"
        params.append(limit)
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return [self._case_dict(row) for row in cursor.fetchall()]
        finally:
            connection.close()

    def get_finding_case(self, case_id: int) -> dict[str, Any] | None:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(self._case_select() + " WHERE c.id=%s", (case_id,))
                row = cursor.fetchone()
                return self._case_dict(row) if row else None
        finally:
            connection.close()

    def update_finding_case(
        self,
        case_id: int,
        update: FindingReviewUpdate,
        actor: str,
    ) -> dict[str, Any] | None:
        connection = self.connect()
        try:
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM finding_cases WHERE id=%s FOR UPDATE", (case_id,))
                current = cursor.fetchone()
                if current is None:
                    connection.rollback()
                    return None
                retested_at = now_sql() if update.mark_retested else current["last_retested_at"]
                tags_json = json.dumps(list(update.tags), ensure_ascii=False)
                cursor.execute(
                    """
                    UPDATE finding_cases SET review_status=%s,assignee=%s,notes=%s,tags_json=%s,
                        evidence_summary=%s,last_retested_at=%s,updated_at=%s WHERE id=%s
                    """,
                    (
                        update.status.value,
                        update.assignee,
                        update.notes,
                        tags_json,
                        update.evidence_summary,
                        retested_at,
                        now_sql(),
                        case_id,
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO finding_case_events(
                        case_id,actor,old_status,new_status,assignee,notes,tags_json,
                        evidence_summary,created_at
                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        case_id,
                        actor,
                        current["review_status"],
                        update.status.value,
                        update.assignee,
                        update.notes,
                        tags_json,
                        update.evidence_summary,
                        now_sql(),
                    ),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_finding_case(case_id)

    def list_finding_case_events(self, case_id: int) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM finding_case_events WHERE case_id=%s ORDER BY id DESC",
                    (case_id,),
                )
                rows = [serialize_row(row) for row in cursor.fetchall()]
                for row in rows:
                    row["tags"] = json.loads(row.pop("tags_json") or "[]")
                return rows
        finally:
            connection.close()

    def dashboard_stats(self) -> dict[str, int]:
        queries = {
            "tasks": "SELECT COUNT(*) AS count FROM tasks",
            "running": "SELECT COUNT(*) AS count FROM tasks WHERE status IN ('QUEUED','RUNNING')",
            "assets": "SELECT COUNT(*) AS count FROM assets",
            "findings": "SELECT COUNT(*) AS count FROM findings",
            "p1": "SELECT COUNT(*) AS count FROM findings WHERE priority='P1'",
            "p2": "SELECT COUNT(*) AS count FROM findings WHERE priority='P2'",
            "roots": "SELECT COUNT(DISTINCT root_domain) AS count FROM assets",
            "subdomains": "SELECT COUNT(DISTINCT subdomain) AS count FROM assets",
        }
        result: dict[str, int] = {}
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                for key, query in queries.items():
                    cursor.execute(query)
                    result[key] = int(cursor.fetchone()["count"])
        finally:
            connection.close()
        return result

    @staticmethod
    def _task_dict(row: dict[str, Any]) -> dict[str, Any]:
        data = serialize_row(row)
        data["config"] = json.loads(data.pop("config_json"))
        data["counts"] = json.loads(data.pop("counts_json"))
        return data
