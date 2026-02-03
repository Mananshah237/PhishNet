from fastapi import FastAPI

app = FastAPI(title="PhishNet API", version="0.1.0")


@app.get("/health")
def health():
    return {"ok": True}
