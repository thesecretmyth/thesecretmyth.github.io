import sys

try:
    # Updated class name for kppy legacy support
    from kppy.database import KPDBv1
except ImportError:
    print("Error: kppy library is missing or configured incorrectly.")
    sys.exit(1)

try:
    # Open legacy 1.x KDB format using KPDBv1
    db = KPDBv1(filepath='Database.kdb', password='eJ6jSnz1z7T4chkJ')
    db.load()

    print("Decryption Successful! Extracting entries:\n")
    print("=" * 60)

    for entry in db.entries:
        print(f"Group:    {entry.group}")
        print(f"Title:    {entry.title}")
        print(f"Username: {entry.username}")
        print(f"Password: {entry.password}")
        print("-" * 60)

except Exception as e:
    print(f"System Error: {e}")
