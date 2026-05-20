from fastapi import HTTPException
from starlette.status import HTTP_400_BAD_REQUEST

from src._confs._fastapi._vos.detail_vo import DetailVo


class BadRequestHTTPExceptionVo(HTTPException):
    def __init__(self, detail: DetailVo = None) -> None:
        super().__init__(HTTP_400_BAD_REQUEST, detail, None)
