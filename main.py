from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt

app = FastAPI()

# --- ASSIGNED VALUES FROM YOUR ASSIGNMENT ---
# Keeping the exact public key string format
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ASSIGNED_ISSUER = "https://idp.exam.local"
ASSIGNED_AUDIENCE = "tds-jxshkdfw.apps.exam.local"

# Define what the incoming request data should look like
class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(payload: TokenRequest):
    try:
        # PyJWT handles all 4 requirements automatically:
        # 1. Signature check using the RS256 key
        # 2. Issuer verification (iss)
        # 3. Audience verification (aud)
        # 4. Expiration time check (exp)
        decoded_claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=ASSIGNED_AUDIENCE,
            issuer=ASSIGNED_ISSUER
        )
        
        # If no exceptions were raised, the token is perfectly valid!
        return {
            "valid": True,
            "email": decoded_claims.get("email"),
            "sub": decoded_claims.get("sub"),
            "aud": decoded_claims.get("aud")
        }
        
    except Exception:
        # Catch ANY token validation failure or environment error 
        # and return a clean JSON structure without the "detail" wrapper
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"valid": False}
        )
