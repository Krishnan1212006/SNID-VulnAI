# vulnerable_app.py
# A lightweight FastAPI app designed to deliberately omit security headers,
# use weak cookies, echo back vulnerable server metrics, and allow open CORS.
# This serves as the Phase 3 local controlled test target.

from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI()

# 1. CORS Misconfiguration (Access-Control-Allow-Origin: *)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Vulnerable setting
    allow_methods=["*"], 
    allow_headers=["*"],
)

@app.middleware("http")
async def add_vulnerable_headers(request: Request, call_next):
    response = await call_next(request)
    # 2. Server Disclosure
    response.headers["Server"] = "VulnTest/1.0"
    # 3. X-Powered-By
    response.headers["X-Powered-By"] = "FastAPI-Undisclosed"
    
    # 4. Explicitly omit security headers like HSTS, X-Frame-Options, CSP, X-Content-Type-Options
    if "X-Frame-Options" in response.headers:
        del response.headers["X-Frame-Options"]
    if "X-Content-Type-Options" in response.headers:
        del response.headers["X-Content-Type-Options"]
        
    return response

@app.get("/")
def read_root(response: Response):
    # 5. Insecure Cookies set (Missing Secure and HttpOnly flags)
    response.set_cookie(key="session_token", value="super_secret_token", secure=False, httponly=False)
    
    # 6. Mixed Content 
    html_content = """
    <html>
        <head>
            <title>Vulnerable App</title>
        </head>
        <body>
            <h1>Welcome to the test target.</h1>
            <p>This page loads an insecure image below.</p>
            <img src="http://example.com/insecure.png" alt="Insecure Mixed Content" />
            <script src="http://example.com/insecure.js"></script>
        </body>
    </html>
    """
    response.headers["Content-Type"] = "text/html"
    return HTMLResponse(content=html_content)

from fastapi.responses import HTMLResponse

if __name__ == "__main__":
    print("Starting Vulnerable Test App on http://127.0.0.1:8001")
    uvicorn.run(app, host="127.0.0.1", port=8001)
