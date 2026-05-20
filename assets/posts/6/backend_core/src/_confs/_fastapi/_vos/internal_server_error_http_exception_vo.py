from typing import Dict

from fastapi import HTTPException
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from src._confs._fastapi._vos.detail_vo import DetailVo


class InternalServerErrorHTTPExceptionVo(HTTPException):
    def __init__(
        self,
        detail: DetailVo = None,
        headers: Dict[str, str] | None = None,
    ) -> None:
        super().__init__(HTTP_500_INTERNAL_SERVER_ERROR, detail, headers)
