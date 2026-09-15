import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field

Decision = Literal["allow", "deny", "approval_required"]
Risk = Literal["low", "medium", "high", "critical"]

class AuthorizationRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=200)
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=200)
    risk: Risk = "low"
    amount: float = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)

class AuthorizationResponse(BaseModel):
    decision: Decision
    reason: str
    policy_id: str
    request_id: str

DESTRUCTIVE_ACTIONS = {"db.delete", "file.delete", "account.disable", "user.delete", "production.deploy_force"}
FINANCIAL_ACTIONS = {"payment.send", "payment.refund", "payout.create", "purchase.create"}
HIGH_RISK_ACTIONS = {"email.send", "message.send", "code.execute", "production.deploy"}
READ_ACTIONS = {"db.read", "file.read", "crm.read", "calendar.read"}
DB_PATH = Path(os.getenv("AGENTOS_DB_PATH", "/app/agentos.db"))
API_KEY = os.getenv("AGENTOS_API_KEY")

# Fail safely: require API key to be configured
if not API_KEY:
    raise RuntimeError(
        "AGENTOS_API_KEY environment variable is not set. "
        "Cannot start service without authentication configured."
    )

app = FastAPI(
    title="AgentOS",
    version="0.1.0",
    description="Authorization + audit gateway for AI-agent actions",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                request_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                risk TEXT NOT NULL,
                amount REAL NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                policy_id TEXT NOT NULL
            )
            """
        )
        conn.commit()


def write_event(event: dict[str, Any]) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["request_id"], event["timestamp"], event["agent_id"], event["action"],
                event["resource"], event["risk"], event["amount"], event["decision"],
                event["reason"], event["policy_id"],
            ),
        )
        conn.commit()


def recent_events(limit: int = 50) -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def evaluate(req: AuthorizationRequest) -> tuple[Decision, str, str]:
    if req.action in DESTRUCTIVE_ACTIONS or req.risk == "critical":
        return "deny", "Destructive or critical actions are blocked by default.", "starter-v1"
    if req.action in FINANCIAL_ACTIONS:
        if req.amount > 1000:
            return "approval_required", "Financial actions above $1,000 require human approval.", "starter-v1"
        return "approval_required", "Financial actions require human approval.", "starter-v1"
    if req.action in HIGH_RISK_ACTIONS or req.risk == "high":
        return "approval_required", "High-risk writes require human approval.", "starter-v1"
    if req.action in READ_ACTIONS or req.risk in {"low", "medium"}:
        return "allow", "Action is within the starter least-privilege policy.", "starter-v1"
    return "deny", "No matching policy rule; default deny.", "starter-v1"


@app.on_event("startup")
def startup() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db()


def auth(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> None:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not secrets.compare_digest(credentials.credentials, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "AgentOS", "status": "ok", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agentos", "version": "0.1.0"}


@app.post(
    "/v1/authorize",
    response_model=AuthorizationResponse,
    dependencies=[Depends(auth)],
)
def authorize(req: AuthorizationRequest) -> AuthorizationResponse:
    decision, reason, policy_id = evaluate(req)
    request_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    write_event({
        "request_id": request_id,
        "timestamp": timestamp,
        "agent_id": req.agent_id,
        "action": req.action,
        "resource": req.resource,
        "risk": req.risk,
        "amount": req.amount,
        "decision": decision,
        "reason": reason,
        "policy_id": policy_id,
    })
    return AuthorizationResponse(
        decision=decision,
        reason=reason,
        policy_id=policy_id,
        request_id=request_id,
    )


@app.get("/v1/audit", dependencies=[Depends(auth)])
def audit(limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
    return recent_events(limit)


def custom_openapi():
    """Generate OpenAPI schema with explicit HTTPBearer security scheme."""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="AgentOS",
        version="0.1.0",
        description="Authorization + audit gateway for AI-agent actions",
        routes=app.routes,
    )
    
    # Define the HTTPBearer security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer",
        }
    }
    
    # Apply security requirement to protected endpoints
    openapi_schema["paths"]["/v1/authorize"]["post"]["security"] = [{"HTTPBearer": []}]
    openapi_schema["paths"]["/v1/audit"]["get"]["security"] = [{"HTTPBearer": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

