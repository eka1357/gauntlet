"""SQLite data models (sqlmodel).

Tables:
    Run     — a hardening run with config, status, cost
    Attack  — individual attack with trace and outcome
    Cluster — breach cluster with root cause analysis
    Policy  — generated hardening policy
    Eval    — before/after evaluation metrics
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlmodel import Field, SQLModel, create_engine


class Run(SQLModel, table=True):
    """A single hardening run."""

    id: str = Field(primary_key=True)
    status: str = Field(default="pending")
    seed: int | None = Field(default=None)
    config_json: str = Field(default="{}")
    created_at: str = Field(default="")
    cost_usd: float = Field(default=0.0)


class Attack(SQLModel, table=True):
    """An individual attack attempt."""

    id: str = Field(primary_key=True)
    run_id: str = Field(foreign_key="run.id")
    generation: int = Field(default=0)
    parent_id: str | None = Field(default=None)
    channel: str = Field(default="")
    category: str = Field(default="")
    strategy: str = Field(default="")
    payload: str = Field(default="")
    model: str = Field(default="")
    outcome: str = Field(default="pending")
    breach_type: str | None = Field(default=None)
    trace_json: str = Field(default="[]")
    cost_usd: float = Field(default=0.0)
    latency_ms: float = Field(default=0.0)
    payload_exposed: bool = Field(default=False)
    outcome_classification: str = Field(default="ignored")
    near_miss: bool = Field(default=False)
    task_style: str = Field(default="action")
    breach_types_json: str = Field(default="[]")


class Cluster(SQLModel, table=True):
    """A breach cluster grouped by root cause."""

    id: str = Field(primary_key=True)
    run_id: str = Field(foreign_key="run.id")
    title: str = Field(default="")
    severity: str = Field(default="")
    root_cause: str = Field(default="")
    root_cause_type: str = Field(default="")
    attack_ids_json: str = Field(default="[]")
    repro_attack_id: str | None = Field(default=None)


class Policy(SQLModel, table=True):
    """A generated hardening policy."""

    id: str = Field(primary_key=True)
    run_id: str = Field(foreign_key="run.id")
    version: int = Field(default=1)
    yaml: str = Field(default="")
    rationale: str = Field(default="")


class Eval(SQLModel, table=True):
    """Before/after evaluation metrics."""

    id: str = Field(primary_key=True)
    run_id: str = Field(foreign_key="run.id")
    phase: str = Field(default="before")
    n: int = Field(default=0)
    breach_rate: float = Field(default=0.0)
    held_out_breach_rate: float = Field(default=0.0)
    benign_pass_rate: float = Field(default=0.0)
    cost_usd: float = Field(default=0.0)


def init_db(db_path_or_engine: str | Path | Any = "runs/gauntlet.db") -> Any:
    """Initialize database tables and apply backward-compatible schema updates."""
    if isinstance(db_path_or_engine, (str, Path)):
        p = Path(db_path_or_engine)
        p.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(f"sqlite:///{p}")
    else:
        engine = db_path_or_engine

    SQLModel.metadata.create_all(engine)
    try:
        with engine.connect() as conn:
            cursor = conn.connection.cursor()
            cols = [c[1] for c in cursor.execute("PRAGMA table_info(attack)").fetchall()]
            if cols and "strategy" not in cols:
                cursor.execute("ALTER TABLE attack ADD COLUMN strategy TEXT DEFAULT ''")
                conn.connection.commit()
            cluster_cols = [c[1] for c in cursor.execute("PRAGMA table_info(cluster)").fetchall()]
            if cluster_cols and "root_cause_type" not in cluster_cols:
                cursor.execute("ALTER TABLE cluster ADD COLUMN root_cause_type TEXT DEFAULT ''")
                conn.connection.commit()
    except Exception:
        pass
    return engine
