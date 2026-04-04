"""
Settings API — manage LLM config and agent prompts at runtime.
All values are stored in the system_config table (key-value).
Changes take effect immediately on the next analysis call.
"""
from __future__ import annotations
import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import SystemConfig
from backend.config import get_settings

# Import default prompts so the UI can show them when no override exists
from backend.agents.llm_agents import (
    AGENT1_SYSTEM, AGENT1_USER_TMPL,
    AGENT2_SYSTEM, AGENT2_USER_TMPL,
    AGENT3_SYSTEM, AGENT3_USER_TMPL,
    AGENT4_SYSTEM, AGENT4_USER_TMPL,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_env = get_settings()

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULTS: dict[str, str] = {
    # LLM connection
    "llm_api_key":    _env.OPENAI_API_KEY,
    "llm_model":      _env.OPENAI_MODEL,
    "llm_base_url":   _env.OPENAI_BASE_URL,
    "llm_temperature": "0.2",
    # Source code directory for snippet extraction
    "source_code_dir": _env.SOURCE_CODE_DIR,
    # Agent system prompts
    "agent1_system": AGENT1_SYSTEM,
    "agent2_system": AGENT2_SYSTEM,
    "agent3_system": AGENT3_SYSTEM,
    "agent4_system": AGENT4_SYSTEM,
    # Agent user prompt templates
    "agent1_user_tmpl": AGENT1_USER_TMPL,
    "agent2_user_tmpl": AGENT2_USER_TMPL,
    "agent3_user_tmpl": AGENT3_USER_TMPL,
    "agent4_user_tmpl": AGENT4_USER_TMPL,
}


def _get_all(db: Session) -> dict[str, str]:
    """Return merged config: DB overrides on top of DEFAULTS."""
    rows = db.query(SystemConfig).all()
    result = dict(DEFAULTS)
    for row in rows:
        result[row.key] = row.value
    return result


def _set_key(db: Session, key: str, value: str) -> None:
    row = db.query(SystemConfig).filter(SystemConfig.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SystemConfig(key=key, value=value))
    db.commit()


# ── Schemas ───────────────────────────────────────────────────────────────────

class SettingsResponse(BaseModel):
    llm_api_key: str
    llm_model: str
    llm_base_url: str
    llm_temperature: str
    source_code_dir: str
    agent1_system: str
    agent2_system: str
    agent3_system: str
    agent4_system: str
    agent1_user_tmpl: str
    agent2_user_tmpl: str
    agent3_user_tmpl: str
    agent4_user_tmpl: str


class SettingsUpdate(BaseModel):
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_base_url: str | None = None
    llm_temperature: str | None = None
    source_code_dir: str | None = None
    agent1_system: str | None = None
    agent2_system: str | None = None
    agent3_system: str | None = None
    agent4_system: str | None = None
    agent1_user_tmpl: str | None = None
    agent2_user_tmpl: str | None = None
    agent3_user_tmpl: str | None = None
    agent4_user_tmpl: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/settings", response_model=SettingsResponse)
def get_settings_api(db: Session = Depends(get_db)):
    """Return current effective settings (DB overrides or defaults)."""
    cfg = _get_all(db)
    # Mask API key: return placeholder if it looks like a real key
    masked_key = cfg["llm_api_key"]
    if masked_key and masked_key not in ("", "your_openai_api_key_here"):
        masked_key = masked_key[:8] + "****" + masked_key[-4:] if len(masked_key) > 12 else "****"
    return SettingsResponse(
        llm_api_key=masked_key,
        llm_model=cfg["llm_model"],
        llm_base_url=cfg["llm_base_url"],
        llm_temperature=cfg["llm_temperature"],
        source_code_dir=cfg["source_code_dir"],
        agent1_system=cfg["agent1_system"],
        agent2_system=cfg["agent2_system"],
        agent3_system=cfg["agent3_system"],
        agent4_system=cfg["agent4_system"],
        agent1_user_tmpl=cfg["agent1_user_tmpl"],
        agent2_user_tmpl=cfg["agent2_user_tmpl"],
        agent3_user_tmpl=cfg["agent3_user_tmpl"],
        agent4_user_tmpl=cfg["agent4_user_tmpl"],
    )


@router.put("/settings", response_model=SettingsResponse)
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    """
    Update one or more settings. Only provided (non-None) fields are written.
    Changes take effect immediately — next analysis call will use the new values.
    """
    for field, value in payload.model_dump(exclude_none=True).items():
        # Don't overwrite API key with masked placeholder
        if field == "llm_api_key" and "****" in value:
            continue
        _set_key(db, field, value)
    logger.info("System settings updated: %s", list(payload.model_dump(exclude_none=True).keys()))
    return get_settings_api(db)


@router.post("/settings/reset", response_model=SettingsResponse)
def reset_settings(db: Session = Depends(get_db)):
    """Reset all settings to defaults (deletes all DB overrides)."""
    db.query(SystemConfig).delete()
    db.commit()
    return get_settings_api(db)
