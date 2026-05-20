from pydantic import BaseModel

from src._confs._fastapi._vos.detail_vo import DetailVo


class InternalServerErrorVo(BaseModel):
    detail: DetailVo
