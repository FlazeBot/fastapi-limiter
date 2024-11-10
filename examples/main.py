from contextlib import asynccontextmanager
from typing import Annotated, Optional

import redis.asyncio as redis
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, WebSocket
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter, WebSocketRateLimiter

security_Bearer = HTTPBearer()

@asynccontextmanager
async def lifespan(_: FastAPI):
    redis_connection = redis.from_url("redis://localhost:6379", encoding="utf8")
    await FastAPILimiter.init(
        redis=redis_connection,
        authorized_passwords=["secrets_bypass_password", "another_super_secret_bypass_password"],
        query_param_names=["password", "special_param"],
        bearer_token_headers=["bearer"],
        api_key_headers=["Api-Key", "X-API-Key"]
    )
    yield
    await FastAPILimiter.close()


app = FastAPI(lifespan=lifespan)


@app.get("/", dependencies=[Depends(RateLimiter(times=2, seconds=5))])
async def index_get():
    return {"msg": "Hello World"}


@app.post("/", dependencies=[Depends(RateLimiter(times=1, seconds=5))])
async def index_post():
    return {"msg": "Hello World"}


@app.get(
    "/multiple",
    dependencies=[
        Depends(RateLimiter(times=1, seconds=5)),
        Depends(RateLimiter(times=2, seconds=15)),
    ],
)
async def multiple():
    return {"msg": "Hello World"}


@app.get("/bypass_bearer", dependencies=[Depends(RateLimiter(times=2, seconds=5, enable_bypass=True))])
async def bypass_bearer(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security_Bearer)]
):
    return {"msg": credentials.credentials}


@app.get("/bypass_query_params", dependencies=[Depends(RateLimiter(times=2, seconds=5, enable_bypass=True))])
async def bypass_query_params(
        special_param: Optional[str] = None
):
    return {"msg": special_param}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ratelimit = WebSocketRateLimiter(times=1, seconds=5)
    while True:
        try:
            data = await websocket.receive_text()
            await ratelimit(websocket, context_key=data)  # NB: context_key is optional
            await websocket.send_text("Hello, world")
        except HTTPException:
            await websocket.send_text("Hello again")


if __name__ == "__main__":
    uvicorn.run("main:app", debug=True, reload=True)
