from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.scanner import analyze_url

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "result": None
    })

@app.post("/scan", response_class=HTMLResponse)
def scan(request: Request, url: str = Form(...)):
    result = analyze_url(url)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "result": result,
        "url": url
    })
