import os
import sqlite3
from typing import Dict, List, Optional

try:
    from .config import Config
except ImportError:
    from config import Config


class ServerRepository:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.db_path = self.config.SERVER_DB_PATH
        self._ensure_database()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_database(self):
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    group_name TEXT NOT NULL DEFAULT 'default',
                    remark TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(host, port)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_servers_host ON servers(host)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_servers_group_name ON servers(group_name)"
            )

        self._migrate_from_text_file_if_needed()

    def _migrate_from_text_file_if_needed(self):
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(1) AS count FROM servers").fetchone()
            if row["count"] > 0:
                return

        txt_path = self.config.SERVER_LIST_PATH
        if not txt_path or not os.path.exists(txt_path):
            return

        servers_to_import = []
        with open(txt_path, "r", encoding="utf-8") as file_obj:
            for raw_line in file_obj:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = self.parse_server_value(line, self.config.SSH_PORT_DEFAULT)
                if parsed:
                    servers_to_import.append(parsed)

        if not servers_to_import:
            return

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO servers (host, port, enabled, group_name, remark)
                VALUES (?, ?, 1, 'default', '')
                """,
                [(item["host"], item["port"]) for item in servers_to_import],
            )

    @staticmethod
    def parse_server_value(server_value: str, default_port: int = 22):
        server_value = (server_value or "").strip()
        if not server_value:
            return None

        if ":" in server_value:
            host, port_str = server_value.rsplit(":", 1)
            host = host.strip()
            port_str = port_str.strip()
            if not host:
                return None
            try:
                port = int(port_str) if port_str else default_port
            except ValueError:
                return None
        else:
            host = server_value
            port = default_port

        return {"host": host, "port": port}

    def list_servers(self, page: int, page_size: int, search: str = "") -> Dict:
        page = max(page, 1)
        page_size = max(1, min(page_size, self.config.SERVER_PAGE_SIZE_MAX))
        offset = (page - 1) * page_size
        search = (search or "").strip()

        conditions = []
        params: List = []

        if search:
            conditions.append("(host LIKE ? OR CAST(port AS TEXT) LIKE ? OR group_name LIKE ? OR remark LIKE ?)")
            keyword = f"%{search}%"
            params.extend([keyword, keyword, keyword, keyword])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(1) AS count FROM servers {where_clause}",
                params,
            ).fetchone()["count"]

            rows = conn.execute(
                f"""
                SELECT id, host, port, enabled, group_name, remark, created_at, updated_at
                FROM servers
                {where_clause}
                ORDER BY host ASC, port ASC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()

        items = [self._row_to_dict(row) for row in rows]
        return {
            "items": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": (total + page_size - 1) // page_size if total else 0,
            },
        }

    def list_sync_targets(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT host, port
                FROM servers
                WHERE enabled = 1
                ORDER BY host ASC, port ASC
                """
            ).fetchall()
        return [f"{row['host']}:{row['port']}" for row in rows]

    def create_server(self, host: str, port: int, group_name: str = "default", remark: str = "", enabled: bool = True):
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO servers (host, port, enabled, group_name, remark, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (host, port, 1 if enabled else 0, group_name, remark),
            )
            server_id = cursor.lastrowid
            row = conn.execute(
                """
                SELECT id, host, port, enabled, group_name, remark, created_at, updated_at
                FROM servers
                WHERE id = ?
                """,
                (server_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def update_server(self, server_id: int, host: str, port: int, group_name: str = "default", remark: str = "", enabled: bool = True):
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE servers
                SET host = ?, port = ?, enabled = ?, group_name = ?, remark = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (host, port, 1 if enabled else 0, group_name, remark, server_id),
            )
            row = conn.execute(
                """
                SELECT id, host, port, enabled, group_name, remark, created_at, updated_at
                FROM servers
                WHERE id = ?
                """,
                (server_id,),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def delete_server(self, server_id: int):
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return cursor.rowcount > 0

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict:
        return {
            "id": row["id"],
            "host": row["host"],
            "port": row["port"],
            "enabled": bool(row["enabled"]),
            "group_name": row["group_name"],
            "remark": row["remark"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
