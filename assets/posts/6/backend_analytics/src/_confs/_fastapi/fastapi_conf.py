from __future__ import annotations

import traceback
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import cached_property
from typing import AsyncGenerator, Tuple

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from src._confs._envs import envs_conf
from src._confs._fastapi._api.api_ctrl import APICtrl
from src._confs._fastapi._vos.additional_schemas_vo import AdditionalSchemasVo
from src._confs._fastapi._vos.internal_server_error_http_exception_vo import (
    InternalServerErrorHTTPExceptionVo,
)
from src._modules._healthcheck import healthcheck_ctrl


@dataclass(frozen=True)
class FastAPIConf:
    envs_conf: envs_conf.EnvsConf = envs_conf.impl
    ctrls: Tuple[APICtrl, ...] = (healthcheck_ctrl.impl,)

    @cached_property
    def app(self) -> FastAPI:
        fastapi = FastAPI(
            title=" ",
            version=" ",
            openapi_url=f"{self.envs_conf.fastapi_path_prefix}/openapi.json"
            if self.envs_conf.fastapi_docs
            else None,
            docs_url=f"{self.envs_conf.fastapi_path_prefix}/docs"
            if self.envs_conf.fastapi_docs
            else None,
            redoc_url=None,
            lifespan=self._lifespan,
        )
        self._set_session(fastapi)
        self._set_allow_cors(fastapi)
        self._set_exception_handler(fastapi)
        self._set_routes(fastapi)
        self._set_additional_schemas(fastapi)
        self._set_landing_static_files(
            fastapi
        )  # Order matters! Must be executed after the actual routes! The order of route definitions determines the sequence of request handling.
        return fastapi

    def run_server(self) -> None:
        uvicorn.run(
            app=f"{self.__module__}:impl.app",  # Must pass the application as an import string (https://www.uvicorn.org/deployment/#running-programmatically)
            host="0.0.0.0",
            port=self.envs_conf.fastapi_port,
            log_level=self.envs_conf.log_level,
            access_log=False,
            workers=self.envs_conf.fastapi_workers,
        )

    @asynccontextmanager
    async def _lifespan(
        self,
        _: FastAPI,
    ) -> AsyncGenerator[None, None]:
        yield

    def _set_routes(self, fastapi: FastAPI) -> None:
        for ctrl in self.ctrls:
            fastapi.include_router(ctrl.get_router())

    def _set_allow_cors(self, fastapi: FastAPI) -> None:
        if self.envs_conf.fastapi_allow_cors:
            fastapi.add_middleware(
                CORSMiddleware,
                allow_origins=self.envs_conf.fastapi_allow_cors_origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

    def _set_session(self, fastapi: FastAPI) -> None:
        fastapi.add_middleware(
            SessionMiddleware,
            https_only=True,
            secret_key=self.envs_conf.fastapi_session_secret_key,
            same_site=self.envs_conf.fastapi_session_same_site,
        )

    def _set_exception_handler(self, fastapi: FastAPI) -> None:
        @fastapi.exception_handler(
            Exception
        )  # It catches everything except HTTPException and its child exceptions
        async def _(request: Request, e: Exception):
            headers = (
                {
                    "access-control-allow-credentials": "true",
                    "access-control-allow-origin": request.headers.get("Origin"),
                }
                if self.envs_conf.fastapi_allow_cors
                else None
            )
            match e:
                case _ if self.envs_conf.fastapi_show_unhandled_exceptions:
                    e = InternalServerErrorHTTPExceptionVo(
                        traceback.format_exc(),
                        headers,
                    )
                case _:
                    e = InternalServerErrorHTTPExceptionVo(
                        "Please try again later. If the issue persists, contact support",
                        headers,
                    )
            return await http_exception_handler(request, e)

    def _set_additional_schemas(self, fastapi: FastAPI) -> None:
        schema_generator_fastapi = FastAPI()

        @schema_generator_fastapi.get("/")
        def _() -> AdditionalSchemasVo: ...

        schema_generator_openapi = schema_generator_fastapi.openapi()
        components = schema_generator_openapi.get("components")
        additional_schemas = components.get("schemas") if components else None
        if additional_schemas:
            fastapi_openapi_schema = fastapi.openapi()
            components = fastapi_openapi_schema.setdefault("components", {})
            schemas = components.setdefault("schemas", {})
            components["schemas"] = schemas | additional_schemas

    def _set_landing_static_files(self, fastapi: FastAPI) -> None:
        # fastapi.mount(...)
        # ...
        return None


impl = FastAPIConf()
