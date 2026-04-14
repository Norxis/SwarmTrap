import uvicorn

from .app import app
from .config import SETTINGS


if __name__ == "__main__":
    uvicorn.run(app, host=SETTINGS.api_host, port=SETTINGS.api_port)
