import asyncio
import copy
import json
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from app.core.config import settings
from app.core.ids import ObjectId

_TABLE = "vulnai_documents"
_pool = None
_database: "PostgresDatabase | None" = None


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _jsonb(value: Any):
    from psycopg.types.json import Jsonb

    return Jsonb(value, dumps=lambda item: json.dumps(item, default=_json_default))


def _decode_document(data: dict[str, Any]) -> dict[str, Any]:
    def restore(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {name: restore(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [restore(item) for item in value]
        if isinstance(value, str) and (key.endswith("_at") or key == "timestamp"):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return value

    return restore(data)


def _field_sql(field: str) -> tuple[str, list[Any]]:
    if field == "_id":
        return "id", []
    return "data #> %s::text[]", [field.split(".")]


def _compile_filter(query: dict[str, Any] | None) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for field, expected in (query or {}).items():
        if field in ("$or", "$and"):
            nested = [_compile_filter(item) for item in expected]
            if nested:
                joiner = " OR " if field == "$or" else " AND "
                clauses.append("(" + joiner.join(clause for clause, _ in nested) + ")")
                for _, nested_params in nested:
                    params.extend(nested_params)
            continue

        expression, path_params = _field_sql(field)
        operators = expected if isinstance(expected, dict) and any(str(key).startswith("$") for key in expected) else {"$eq": expected}
        for operator, value in operators.items():
            if operator == "$exists":
                if field == "_id":
                    clauses.append("TRUE" if value else "FALSE")
                else:
                    clauses.append(f"({expression} IS {'NOT ' if value else ''}NULL)")
                    params.extend(path_params)
            elif operator == "$in":
                if field == "_id":
                    clauses.append("id = ANY(%s)")
                    params.append([str(item) for item in value])
                else:
                    clauses.append(f"{expression} IN (SELECT value FROM jsonb_array_elements(%s::jsonb))")
                    params.extend(path_params)
                    params.append(_jsonb(value))
            elif operator in ("$eq", "$ne", "$gt", "$gte", "$lt", "$lte"):
                sql_operator = {
                    "$eq": "=", "$ne": "IS DISTINCT FROM", "$gt": ">",
                    "$gte": ">=", "$lt": "<", "$lte": "<=",
                }[operator]
                if field == "_id":
                    clauses.append(f"id {sql_operator} %s")
                    params.append(str(value))
                else:
                    clauses.append(f"{expression} {sql_operator} %s::jsonb")
                    params.extend(path_params)
                    params.append(_jsonb(value))
            elif operator == "$regex":
                clauses.append(f"{expression} #>> '{{}}' ~* %s")
                params.extend(path_params)
                params.append(str(value))
            else:
                raise ValueError(f"Unsupported document filter operator: {operator}")

    return " AND ".join(clauses) if clauses else "TRUE", params


def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    current = document
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def _unset_path(document: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    current = document
    for part in parts[:-1]:
        current = current.get(part)
        if not isinstance(current, dict):
            return
    current.pop(parts[-1], None)


class PostgresCursor:
    def __init__(self, collection, query=None, projection=None, records=None) -> None:
        self.collection = collection
        self.query = query or {}
        self.projection = projection
        self.records = records
        self.sort_spec: list[tuple[str, int]] = []
        self.limit_count: int | None = None
        self.skip_count = 0

    def sort(self, key_or_list, direction=None):
        if isinstance(key_or_list, str):
            self.sort_spec = [(key_or_list, direction or 1)]
        else:
            self.sort_spec = list(key_or_list)
        return self

    def limit(self, count: int):
        self.limit_count = count
        return self

    def skip(self, count: int):
        self.skip_count = count
        return self

    async def to_list(self, length: int | None = None) -> list[dict[str, Any]]:
        limit = self.limit_count
        if length is not None:
            limit = length if limit is None else min(length, limit)
        if self.records is None:
            documents = await self.collection._find(self.query, self.sort_spec, self.skip_count, limit)
        else:
            documents = self.records
            for field, direction in reversed(self.sort_spec):
                documents.sort(key=lambda item: item.get(field), reverse=direction < 0)
            documents = documents[self.skip_count:]
            if limit is not None:
                documents = documents[:limit]
        return [self.collection._project(item, self.projection) for item in documents]


class PostgresCollection:
    def __init__(self, name: str, pool) -> None:
        self.name = name
        self.pool = pool

    def _execute_with_retry(self, fn, max_attempts: int = 2):
        from psycopg import OperationalError
        for attempt in range(max_attempts):
            try:
                return fn()
            except OperationalError:
                if attempt == max_attempts - 1:
                    raise

    @staticmethod
    def _project(document: dict[str, Any], projection: dict[str, int] | None) -> dict[str, Any]:
        if not projection:
            return document
        included = {key for key, enabled in projection.items() if enabled}
        if included:
            result = {key: document[key] for key in included if key in document}
            if projection.get("_id", 1) and "_id" in document:
                result["_id"] = document["_id"]
            return result
        return {key: value for key, value in document.items() if not projection.get(key)}

    async def insert_one(self, document: dict[str, Any]) -> SimpleNamespace:
        stored = dict(document)
        identifier = str(stored.setdefault("_id", ObjectId()))
        def insert() -> None:
            with self.pool.connection() as connection:
                connection.execute(
                    f"INSERT INTO {_TABLE} (collection, id, data) VALUES (%s, %s, %s)",
                    (self.name, identifier, _jsonb(stored)),
                )

        await asyncio.to_thread(self._execute_with_retry, insert)
        document["_id"] = ObjectId(identifier)
        return SimpleNamespace(inserted_id=ObjectId(identifier))

    async def insert_many(self, documents: list[dict[str, Any]]) -> SimpleNamespace:
        inserted_ids = []

        def insert() -> None:
            with self.pool.connection() as connection:
                with connection.transaction():
                    for document in documents:
                        stored = dict(document)
                        identifier = str(stored.setdefault("_id", ObjectId()))
                        connection.execute(
                            f"INSERT INTO {_TABLE} (collection, id, data) VALUES (%s, %s, %s)",
                            (self.name, identifier, _jsonb(stored)),
                        )
                        document["_id"] = ObjectId(identifier)
                        inserted_ids.append(ObjectId(identifier))

        await asyncio.to_thread(self._execute_with_retry, insert)
        return SimpleNamespace(inserted_ids=inserted_ids)

    def find(self, query=None, projection=None) -> PostgresCursor:
        return PostgresCursor(self, query, projection)

    async def find_one(self, query=None, projection=None, sort=None):
        cursor = self.find(query, projection)
        if sort:
            cursor.sort(sort)
        documents = await cursor.limit(1).to_list(length=1)
        return documents[0] if documents else None

    async def _find(self, query, sort_spec, skip, limit):
        where, params = _compile_filter(query)
        sql = f"SELECT data FROM {_TABLE} WHERE collection = %s AND ({where})"
        args = [self.name, *params]
        if sort_spec:
            order = []
            for field, direction in sort_spec:
                expression, path_params = _field_sql(field)
                order.append(f"{expression} {'DESC' if direction < 0 else 'ASC'} NULLS LAST")
                args.extend(path_params)
            sql += " ORDER BY " + ", ".join(order)
        if limit is not None:
            sql += " LIMIT %s"
            args.append(max(0, limit))
        if skip:
            sql += " OFFSET %s"
            args.append(max(0, skip))

        def fetch() -> list[dict[str, Any]]:
            with self.pool.connection() as connection:
                cursor = connection.execute(sql, args)
                return [_decode_document(row["data"]) for row in cursor.fetchall()]

        return await asyncio.to_thread(self._execute_with_retry, fetch)

    async def count_documents(self, query=None) -> int:
        where, params = _compile_filter(query)

        def count() -> int:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"SELECT COUNT(*) AS count FROM {_TABLE} WHERE collection = %s AND ({where})",
                    [self.name, *params],
                )
                return cursor.fetchone()["count"]

        return await asyncio.to_thread(self._execute_with_retry, count)

    async def update_one(self, query, update, upsert: bool = False) -> SimpleNamespace:
        where, params = _compile_filter(query)

        def update_document() -> SimpleNamespace:
            with self.pool.connection() as connection:
                with connection.transaction():
                    cursor = connection.execute(
                        f"SELECT id, data FROM {_TABLE} WHERE collection = %s AND ({where}) LIMIT 1 FOR UPDATE",
                        [self.name, *params],
                    )
                    row = cursor.fetchone()
                    if row is None:
                        if not upsert:
                            return SimpleNamespace(matched_count=0, modified_count=0)
                        document = copy.deepcopy(query) if isinstance(query, dict) else {}
                        document = {k: v for k, v in document.items() if not str(k).startswith("$") and not isinstance(v, dict)}
                        changes = update.get("$set", update if not any(key.startswith("$") for key in update) else {})
                        for field, value in changes.items():
                            _set_path(document, field, value)
                        identifier = str(document.setdefault("_id", ObjectId()))
                        connection.execute(
                            f"INSERT INTO {_TABLE} (collection, id, data) VALUES (%s, %s, %s)",
                            (self.name, identifier, _jsonb(document)),
                        )
                        return SimpleNamespace(matched_count=0, modified_count=1, upserted_id=ObjectId(identifier))
                    original = _decode_document(row["data"])
                    document = copy.deepcopy(original)
                    changes = update.get("$set", update if not any(key.startswith("$") for key in update) else {})
                    for field, value in changes.items():
                        _set_path(document, field, value)
                    for field, amount in update.get("$inc", {}).items():
                        _set_path(document, field, document.get(field, 0) + amount)
                    for field, value in update.get("$push", {}).items():
                        values = document.setdefault(field, [])
                        if isinstance(value, dict) and "$each" in value:
                            values.extend(value["$each"])
                        else:
                            values.append(value)
                    for field in update.get("$unset", {}):
                        _unset_path(document, field)
                    changed = document != original
                    if changed:
                        connection.execute(
                            f"UPDATE {_TABLE} SET data = %s WHERE collection = %s AND id = %s",
                            (_jsonb(document), self.name, row["id"]),
                        )
                    return SimpleNamespace(matched_count=1, modified_count=int(changed))

        return await asyncio.to_thread(self._execute_with_retry, update_document)

    async def delete_one(self, query) -> SimpleNamespace:
        where, params = _compile_filter(query)

        def delete() -> SimpleNamespace:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"WITH target AS (SELECT id FROM {_TABLE} WHERE collection = %s AND ({where}) LIMIT 1) "
                    f"DELETE FROM {_TABLE} d USING target t WHERE d.collection = %s AND d.id = t.id",
                    [self.name, *params, self.name],
                )
                return SimpleNamespace(deleted_count=cursor.rowcount)

        return await asyncio.to_thread(self._execute_with_retry, delete)

    async def delete_many(self, query=None) -> SimpleNamespace:
        where, params = _compile_filter(query)

        def delete() -> SimpleNamespace:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"DELETE FROM {_TABLE} WHERE collection = %s AND ({where})",
                    [self.name, *params],
                )
                return SimpleNamespace(deleted_count=cursor.rowcount)

        return await asyncio.to_thread(self._execute_with_retry, delete)

    async def aggregate(self, pipeline) -> PostgresCursor:
        match = next((stage["$match"] for stage in pipeline if "$match" in stage), {})
        group = next((stage["$group"] for stage in pipeline if "$group" in stage), None)
        if not group or not isinstance(group.get("_id"), str) or not group["_id"].startswith("$"):
            raise ValueError("Only field grouping is supported by the Postgres document store")
        expression, path_params = _field_sql(group["_id"][1:])
        where, params = _compile_filter(match)

        def aggregate() -> list[dict[str, Any]]:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"SELECT {expression} AS _id, COUNT(*) AS count FROM {_TABLE} "
                    f"WHERE collection = %s AND ({where}) GROUP BY {expression}",
                    [*path_params, self.name, *params, *path_params],
                )
                return [{"_id": row["_id"], "count": row["count"]} for row in cursor.fetchall()]

        return PostgresCursor(self, records=await asyncio.to_thread(aggregate))


    async def delete_one(self, query) -> SimpleNamespace:
        where, params = _compile_filter(query)

        def delete() -> SimpleNamespace:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"WITH target AS (SELECT id FROM {_TABLE} WHERE collection = %s AND ({where}) LIMIT 1) "
                    f"DELETE FROM {_TABLE} d USING target t WHERE d.collection = %s AND d.id = t.id",
                    [self.name, *params, self.name],
                )
                return SimpleNamespace(deleted_count=cursor.rowcount)

        return await asyncio.to_thread(delete)

    async def delete_many(self, query=None) -> SimpleNamespace:
        where, params = _compile_filter(query)

        def delete() -> SimpleNamespace:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"DELETE FROM {_TABLE} WHERE collection = %s AND ({where})",
                    [self.name, *params],
                )
                return SimpleNamespace(deleted_count=cursor.rowcount)

        return await asyncio.to_thread(delete)

    async def aggregate(self, pipeline) -> PostgresCursor:
        match = next((stage["$match"] for stage in pipeline if "$match" in stage), {})
        group = next((stage["$group"] for stage in pipeline if "$group" in stage), None)
        if not group or not isinstance(group.get("_id"), str) or not group["_id"].startswith("$"):
            raise ValueError("Only field grouping is supported by the Postgres document store")
        expression, path_params = _field_sql(group["_id"][1:])
        where, params = _compile_filter(match)

        def aggregate() -> list[dict[str, Any]]:
            with self.pool.connection() as connection:
                cursor = connection.execute(
                    f"SELECT {expression} AS _id, COUNT(*) AS count FROM {_TABLE} "
                    f"WHERE collection = %s AND ({where}) GROUP BY 1",
                    [*path_params, self.name, *params],
                )
                return [{"_id": _decode_document(row["_id"]) if isinstance(row["_id"], dict) else row["_id"], "count": row["count"]} for row in cursor.fetchall()]

        return PostgresCursor(self, records=await asyncio.to_thread(self._execute_with_retry, aggregate))


class PostgresDatabase:
    def __init__(self, pool) -> None:
        self.pool = pool

    def __getattr__(self, collection: str) -> PostgresCollection:
        if collection.startswith("_"):
            raise AttributeError(collection)
        return PostgresCollection(collection, self.pool)


async def connect_to_postgres() -> None:
    global _pool, _database
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL must be set to your Neon Postgres connection string")
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(
        conninfo=settings.database_url,
        kwargs={"row_factory": dict_row, "prepare_threshold": None},
        min_size=1,
        max_size=10,
        max_idle=60,
        max_lifetime=300,
        check=ConnectionPool.check_connection,
        open=False,
    )

    def initialize() -> None:
        pool.open(wait=True)
        with pool.connection() as connection:
            connection.execute(
                f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
                "collection TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL, "
                "PRIMARY KEY (collection, id))"
            )
            connection.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_data ON {_TABLE} USING GIN (data)"
            )
            connection.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{_TABLE}_user_email "
                f"ON {_TABLE} ((data->>'email')) WHERE collection = 'users'"
            )

    try:
        await asyncio.to_thread(initialize)
    except Exception:
        await asyncio.to_thread(pool.close)
        raise
    _pool = pool
    _database = PostgresDatabase(_pool)
    print("Connected to Neon Postgres")


async def close_postgres_connection() -> None:
    global _pool, _database
    if _pool is not None:
        await asyncio.to_thread(_pool.close)
        _pool = None
        _database = None
        print("Neon Postgres connection closed")


def get_database() -> PostgresDatabase:
    if _database is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=503,
            detail="Neon Postgres is unavailable; configure DATABASE_URL and verify connectivity",
        )
    return _database