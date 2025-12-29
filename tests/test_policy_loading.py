
# Importing necessary libraries, including our own from relative path
from src.policy import LoadPolicy
import json

# TempPath is temporary directory created by pytest()
def test_policy_loads_valid_file(tmp_path):
    PolicyFile = tmp_path / "policy.json"
    PolicyFile.write_text(json.dumps({"rules": {}}))

    Policy = LoadPolicy(str(PolicyFile))

    # Confirms rules property returns the expected value
    assert Policy.rules == {}