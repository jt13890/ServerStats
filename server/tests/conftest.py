import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))

# Expose the agent's collector to tests as a module.
spec = importlib.util.spec_from_file_location("agent_collector", ROOT / "agent" / "serverstats_agent.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.modules["agent_collector"] = module
