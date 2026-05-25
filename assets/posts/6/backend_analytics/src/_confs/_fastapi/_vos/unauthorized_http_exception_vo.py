from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED

from src._confs._fastapi._vos.detail_vo import DetailVo


class UnauthorizedHTTPExceptionVo(HTTPException):
    def __init__(self, detail: DetailVo = None) -> None:
        super().__init__(HTTP_401_UNAUTHORIZED, detail, None)
