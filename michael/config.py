import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
# Used in order when the main model's daily free-tier budget runs out.
AGENT_FALLBACKS = ["openai/gpt-oss-20b", "qwen/qwen3.8-27b"]
NO_REASONING = {"qwen/qwen3.8-27b"}

# Max reasoning/tool steps the agent may take for a single user request.
MAX_AGENT_STEPS = 6
