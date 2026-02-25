# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

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
