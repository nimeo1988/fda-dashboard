from sqlalchemy import Column, Integer, String, Text
from .database import Base

class ScanResult(Base):
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    verdict = Column(String)
    js_hits = Column(Text)
    phishing_hits = Column(Text)
    redirects = Column(Text)
    screenshot = Column(String)
