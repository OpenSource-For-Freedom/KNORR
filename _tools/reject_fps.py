import sys
sys.path.insert(0, r'F:\dev\knorr\src')

from knorr.db import Database
from knorr import config

db = Database.open(config.DB_PATH)

fps = [
    'isukim/kargos-agent',
    'isukim/plasma-compute',
    'isukim/plasma-control',
    'isukim/tracing_api_test',
    'isukim/api-jaeger-testing',
]

for img in fps:
    db.conn.execute(
        "UPDATE image_findings SET status='rejected' WHERE image=?", (img,))

db.conn.commit()

rows = db.conn.execute(
    "SELECT image, status FROM image_findings WHERE image LIKE 'isukim/%' ORDER BY image"
).fetchall()

print("isukim cluster status:")
for r in rows:
    print(f"  {r[0]:45s}  {r[1]}")

confirmed = db.confirmed()
print(f"\nTotal confirmed in DB: {len(confirmed)}")
db.close()
