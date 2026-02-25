import secrets

from starlette.middleware.sessions import SessionMiddleware


def add_middlewares(app):
    session_secret = secrets.token_hex(16)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        same_site="lax",
        https_only=True,
    )
