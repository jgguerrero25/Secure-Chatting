import asyncio
import ssl
import time
import json

from aiohttp import web, WSMsgType
import jwt

JWT_SECRET = "CHANGE_ME"
JWT_ALGO = "HS256"
JWT_EXP_SECONDS = 1800
PING_INTERVAL = 20

USERS = {
    "Jonathan Guerrero": "JonathanPass",
    "bob": "bobpass",
    "alice": "alicepass",
}

CONNECTED = {}  # ws -> username

LOGIN_LIMITERS = {}
WS_LIMITERS = {}

LOGIN_CAPACITY = 5
LOGIN_REFILL_PER_SEC = 5/60

CHAT_CAPACITY = 3
CHAT_REFILL_PER_SEC = 1

TYPING_CAPACITY = 3
TYPING_REFILL_PER_SEC = 1

class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now

        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


def make_jwt(username):
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + JWT_EXP_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])["sub"]
    except:
        return None

async def login(request):
    ip = request.headers.get("X-Forwarded-For", request.remote) or "unknown"

    limiter = LOGIN_LIMITERS.get(ip)
    if limiter is None:
        limiter = LOGIN_LIMITERS[ip] = TokenBucket(LOGIN_CAPACITY, LOGIN_REFILL_PER_SEC)

    if not limiter.allow():
        return web.json_response({"error": "rate_limited"}, status=429)

    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if username not in USERS or USERS[username] != password:
        return web.json_response({"error": "invalid_credentials"}, status=401)

    token = make_jwt(username)
    return web.json_response({"token": token})

async def broadcast(event, data, exclude=None):
    msg = json.dumps({"type": event, "data": data})
    dead = []

    for ws in list(CONNECTED.keys()):
        if ws is exclude:
            continue
        try:
            await ws.send_str(msg)
        except:
            dead.append(ws)

    for ws in dead:
        CONNECTED.pop(ws, None)

async def websocket_handler(request):
    token = request.query.get("token")
    user = verify_jwt(token)
    if not user:
        return web.Response(status=401, text="Unauthorized")

    ws = web.WebSocketResponse(autoping=False, heartbeat=PING_INTERVAL)
    await ws.prepare(request)

    CONNECTED[ws] = user

    def ws_allow(kind: str) -> bool:
        key = (user, kind)
        lim = WS_LIMITERS.get(key)

        if lim is None:
            if kind == "chat":
                lim = WS_LIMITERS[key] = TokenBucket(CHAT_CAPACITY, CHAT_REFILL_PER_SEC)
            else:  # typing
                lim = WS_LIMITERS[key] = TokenBucket(TYPING_CAPACITY, TYPING_REFILL_PER_SEC)

        return lim.allow()


    # Send full online list to the new user
    await ws.send_str(json.dumps({
        "type": "online_list",
        "data": {"users": list(set(CONNECTED.values()))}
    }))

    # Broadcast join event only if this is the first connection for this user
    if list(CONNECTED.values()).count(user) == 1:
        await broadcast("user_joined", {"user": user}, exclude=ws)

    async def ping_loop():
        while not ws.closed:
            try:
                await ws.ping()
            except:
                break
            await asyncio.sleep(PING_INTERVAL)

    ping_task = asyncio.create_task(ping_loop())

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    payload = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue

                mtype = payload.get("type")

                if mtype == "typing":
                    if not ws_allow("typing"):
                        await ws.send_str(json.dumps({"type": "error", "data": {"error": "rate_limited"}}))
                        continue
                    await broadcast("typing", {"user": user, "isTyping": payload.get("isTyping", False)}, exclude=ws)
                    continue

                if mtype == "chat":
                    if not ws_allow("chat"):
                        await ws.send_str(json.dumps({"type": "error", "data": {"error": "rate_limited"}}))
                        continue
                    await broadcast("chat", {"from": user, "text": payload.get("text", "")}, exclude=ws)
                    continue

    finally:
        old_user = CONNECTED.pop(ws, None)

        if old_user and old_user not in CONNECTED.values():
            await broadcast("user_left", {"user": old_user})

        ping_task.cancel()

    return ws

app = web.Application()

app.router.add_static("/client/", "./client", show_index=False)

async def index(request):
    return web.FileResponse("./client/index.html")

app.router.add_get("/", index)

app.add_routes([
    web.post("/login", login),
    web.get("/ws", websocket_handler),
])

if __name__ == "__main__":
    sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslctx.load_cert_chain("certs/fullchain.pem", "certs/privkey.pem")
    web.run_app(app, host="0.0.0.0", port=8443, ssl_context=sslctx)
