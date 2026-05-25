from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from fastapi import APIRouter
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from src._confs._envs import envs_conf
from src._confs._fastapi._vos.bad_request_vo import BadRequestVo
from src._confs._fastapi._vos.internal_server_error_vo import InternalServerErrorVo
from src._confs._fastapi._vos.unauthorized_vo import UnauthorizedVo


@dataclass(frozen=True)
class APICtrl(ABC):
    envs_conf: envs_conf.EnvsConf = envs_conf.impl

    @abstractmethod
    def set_routes(self, router: APIRouter) -> None: ...

    def get_router(self) -> APIRouter:
        router = self._router()
        self.set_routes(router)
        return router

    def _router(self) -> APIRouter:
        router = APIRouter()
        router.prefix += self.envs_conf.fastapi_path_prefix
        router.responses[HTTP_400_BAD_REQUEST] = {"model": BadRequestVo}
        router.responses[HTTP_401_UNAUTHORIZED] = {"model": UnauthorizedVo}
        router.responses[HTTP_500_INTERNAL_SERVER_ERROR] = {
            "model": InternalServerErrorVo
        }
        return router
