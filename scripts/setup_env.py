"""Create local configuration without printing secrets or overwriting existing config."""
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
target = root / ".env"
if target.exists():
    raise SystemExit(".env already exists; preserved. Edit it manually if needed.")
text = (root / ".env.example").read_text()
text = text.replace("replace-with-at-least-32-random-characters", secrets.token_hex(32))
text = text.replace("replace-with-another-32-random-characters", secrets.token_hex(32))
text = text.replace("local-admin-demo", secrets.token_hex(24)).replace("local-app-demo", secrets.token_hex(24))
target.write_text(text)
print("Created .env with fresh signing, worker, and database secrets. Model mode: mock.")
