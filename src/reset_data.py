import sys
import os

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_ROOT)

from data.ids_data import reset_data


reset_data()

print("Database reset successfully!")
print("Packets: 0")
print("Alerts: 0")