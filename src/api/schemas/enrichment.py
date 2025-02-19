from pydantic import BaseModel, IPvAnyAddress

class IPCheckRequest(BaseModel):
    ip_address: str 