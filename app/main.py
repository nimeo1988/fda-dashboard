from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .database import Base, engine, SessionLocal
from .models import ScanResult
from .scanner import scan_url

Base.metadata.create_all(bind=engine)

app = FastAPI()
templates = Jinja2Templates(directory='app/templates')

app.mount('/static', StaticFiles(directory='app/static'), name='static')

@app.get('/')
def dashboard(request: Request):
    db: Session = SessionLocal()
    scans = db.query(ScanResult).order_by(ScanResult.id.desc()).all()
    db.close()
    return templates.TemplateResponse('dashboard.html', {'request': request, 'scans': scans})

@app.post('/scan')
def scan(request: Request, url: str = Form(...)):
    result = scan_url(url)

    db: Session = SessionLocal()
    scan = ScanResult(
        url=url,
        verdict=result['verdict'],
        js_hits=result['js_hits'],
        phishing_hits=result['phishing_hits'],
        redirects=result['redirects'],
        screenshot=result['screenshot']
    )
    db.add(scan)
    db.commit()
    db.close()

    return dashboard(request)
