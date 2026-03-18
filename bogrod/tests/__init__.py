from pathlib import Path

import os

BASE_PATH = Path.cwd() if 'TOX_ENV_DIR' not in os.environ else Path(os.environ['TOX_ENV_DIR'])
