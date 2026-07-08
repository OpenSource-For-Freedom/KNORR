import sys
sys.path.insert(0, r'F:\dev\knorr\src')
from knorr.db import Database
from knorr import config

db = Database.open(config.DB_PATH)
rows = db.conn.execute(
    "SELECT image, score FROM image_findings WHERE status='screened' ORDER BY score DESC"
).fetchall()
print(f"{len(rows)} screened  (score range {rows[-1][1]}-{rows[0][1]})")
print("\nTop 15:")
for r in rows[:15]:
    print(f"  {r[1]:>3}  {r[0]}")
db.close()
