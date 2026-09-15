import requests

AGENTOS_URL = "https://agentos-production-d0c4.up.railway.app"
API_KEY = "demo-agent-key"

response = requests.post(
    f"{AGENTOS_URL}/v1/authorize",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={
        "agent_id": "demo-agent",
        "action": "db.read",
        "resource": "customer_records",
        "risk": "low",
        "amount": 0,
        "metadata": {},
    },
)

print(response.json())
