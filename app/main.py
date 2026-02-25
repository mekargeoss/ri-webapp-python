# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .a3_client import A3Client
from .config import settings
from .middleware import add_middlewares
from .security import (
    InvalidToken,
    gen_nonce,
    gen_pkce_challenge,
    gen_state,
    verify_token,
)

app = FastAPI(title="Demo Web Application using Mekarge A3")
add_middlewares(app)
templates = Jinja2Templates(directory="app/templates")
a3 = A3Client(settings.issuer, settings.client_id, settings.client_secret)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get("user")
    error = request.session.get("error")
    access_token = request.session.get("access_token")
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "error": error,
            "access_token": access_token,
        },
    )


@app.get("/login")
async def login(request: Request):

    claims_locales = request.query_params.get("claims_locales")
    ui_locales = request.query_params.get("ui_locales")

    state = gen_state()
    nonce = gen_nonce()
    verifier, challenge = gen_pkce_challenge()

    request.session.update(
        {"state": state, "nonce": nonce, "verifier": verifier, "error": None}
    )
    auth_url = await a3.build_authorize_url(
        redirect_uri=settings.redirect_uri,
        scope="openid profile email",
        state=state,
        code_challenge=challenge,
        code_challenge_method="S256",
        nonce=nonce,
        claims_locales=claims_locales,
        ui_locales=ui_locales,
    )
    return RedirectResponse(auth_url)


@app.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    if error is not None:
        request.session["error"] = f"Received error from Mekarege A3 ({error})"
        return RedirectResponse("/")

    if code is None or state is None or state != request.session.get("state"):
        request.session["error"] = "State and/or PKCE test has failed!"
        return RedirectResponse("/")

    tokens = await a3.request_access_token(
        code=code,
        redirect_uri=settings.redirect_uri,
        code_verifier=request.session["verifier"],
        state=state,
    )

    try:
        access_claims = await verify_token_async(
            token=tokens["access_token"],
            nonce=None,
            expected_aud=settings.resource_uri,
        )
        request.session["access_token"] = access_claims
    except InvalidToken as e:
        request.session["error"] = f"Access Token validation has failed ({e})"
        return RedirectResponse("/")

    if tokens.get("id_token") is None:
        request.session["user"] = dict()
        return RedirectResponse("/me")

    try:
        id_claims = await verify_token_async(
            token=tokens["id_token"],
            nonce=request.session["nonce"],
            expected_aud=settings.client_id,
        )
        request.session["user"] = id_claims
    except InvalidToken as e:
        request.session["error"] = f"ID Token validation has failed ({e})"
        return RedirectResponse("/")

    return RedirectResponse("/me")


async def verify_token_async(token: str, nonce: str | None, expected_aud: str):
    jwks = await a3.get_jwks()
    claims = verify_token(
        token=token,
        issuer=settings.issuer,
        nonce=nonce,
        jwks=jwks,
        expected_aud=expected_aud,
    )
    return claims


@app.get("/me", response_class=HTMLResponse)
async def me(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse(
        "profile.html", {"request": request, "user": user}
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")
