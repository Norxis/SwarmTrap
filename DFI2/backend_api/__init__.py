"""DFI2 backend control-plane API package."""

__all__ = ["create_app"]


def create_app():
    from .app import create_app as _create_app

    return _create_app()
