from typing import List, Union, Any, Optional
from pydantic import BaseModel

class NetworkPacket(BaseModel):
    time: float
    src_ip: str
    dst_ip: str
    src_port: Union[int, Any]
    dst_port: Union[int, Any]
    protocol: str
    length: int
    payload: str

class NetworkPacketList(BaseModel):
    packets: List[NetworkPacket]