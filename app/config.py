# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

from .a3_client import A3Issuer

load_dotenv()


@dataclass
class Settings:
    issuer: A3Issuer
    client_id: str
    client_secret: str
    redirect_uri: str
    resource_uri: str


@lru_cache
def get_settings() -> Settings:
    def mandatory(var: str) -> str:
        value = os.getenv(var)
        if value is None:
            raise ValueError(f"{var} is missing")
        return value

    return Settings(
        issuer=A3Issuer(mandatory("ISSUER_PATH")),
        client_id=mandatory("CLIENT_ID"),
        client_secret=mandatory("CLIENT_SECRET"),
        redirect_uri=mandatory("REDIRECT_URI"),
        resource_uri=mandatory("RESOURCE_URI"),
    )


settings = get_settings()
