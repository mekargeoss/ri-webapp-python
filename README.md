# Mekarge Python Web Application RI

Python Web Application reference implementation using Mekarge A3 as Identity Provider. The application validates **Access Tokens** and **Id Tokens** that are signed with `RS256` algorithm using discovery via `.well-known/openid-configuration`.

The main idea behind reference implementation is to use widely adopted libraries instead of private libraries, thereby demonstrating the ease of adoption of Mekarge A3. Major dependencies are:

| Dependency                    | Library       |
| ----------------------------- | ------------- |
| Web Framework                 | `fastapi`     |
| OAuth2 Client                 | `authlib`     |
| Http Client (for discovery)   | `httpx`       |
| JOSE Tooling                  | `python-jose` |

## Requirements

* Python 3.x

## Installation

```bash
python -m venv .venv
```

Activate (macOS / Linux):

```bash
source .venv/bin/activate
```

Activate (Windows):

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Mekarge A3 Configuration

Ensure that the `Client` created in Mekarge A3 has:
* `Client Authentication Type` set as `Post (Http Body)`
* `PKCE` feature enabled
* `OpenID` feature enabled

### Application Configuration

Edit `.env` file to update following environment variables:

| Variable                      | Description   |
| ----------------------------- | ------------- |
| `ISSUER_PATH`                 | Issuer Path given for the target Environment |
| `CLIENT_ID`                   | Client Id |
| `CLIENT_SECRET`               | Client Secret |
| `REDIRECT_URI`                | Redirection URL defined in Client |
| `RESOURCE_URI`                | Resource URI of the target Resource |

### Running Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Development

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

Formatting:

```bash
ruff format .
```

Linter:

```bash
ruff check .
```

Type Checker:

```bash
mypy .
```

### License

MIT
