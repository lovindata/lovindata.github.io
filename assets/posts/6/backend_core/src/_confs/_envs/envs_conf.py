import os
from functools import cached_property
from typing import Literal, Tuple

from dotenv import get_key

from src._confs._envs._vos.invalid_env_runtime_error_vo import InvalidEnvRuntimeErrorVo
from src._confs._envs._vos.missing_env_runtime_error_vo import MissingEnvRuntimeErrorVo


class EnvsConf:
    # Dev
    @cached_property
    def dotenv_path(self) -> str:
        return os.getenv("DOTENV_PATH", "../devops/dev/.env")

    @cached_property
    def log_level(
        self,
    ) -> Literal["critical", "error", "warning", "info", "debug", "trace"]:
        value = os.getenv("LOG_LEVEL", "debug")
        if value in ("critical", "error", "warning", "info", "debug", "trace"):
            return value
        raise InvalidEnvRuntimeErrorVo("LOG_LEVEL", value)

    @cached_property
    def watchfiles(self) -> bool:
        return os.getenv("WATCHFILES", "true") == "true"

    # FastAPI
    @cached_property
    def fastapi_port(self) -> int:
        return int(os.getenv("FASTAPI_PORT", "49158"))

    @cached_property
    def fastapi_workers(self) -> int:
        return int(os.getenv("FASTAPI_WORKERS", "1"))

    @cached_property
    def fastapi_path_prefix(self) -> str:
        return os.getenv("FASTAPI_PATH_PREFIX", "/api")

    @cached_property
    def fastapi_allow_cors(self) -> bool:
        return os.getenv("FASTAPI_ALLOW_CORS", "true") == "true"

    @cached_property
    def fastapi_allow_cors_origins(self) -> Tuple[str, ...]:
        return tuple(
            os.getenv(
                "FASTAPI_ALLOW_CORS_ORIGINS",
                "http://127.0.0.1:3000|http://localhost:3000",
            ).split("|")
        )

    @cached_property
    def fastapi_docs(self) -> bool:
        return os.getenv("FASTAPI_DOCS", "true") == "true"

    @cached_property
    def fastapi_show_unhandled_exceptions(self) -> bool:
        return os.getenv("FASTAPI_SHOW_UNHANDLED_EXCEPTIONS", "true") == "true"

    @cached_property
    def fastapi_session_secret_key(self) -> str:
        return os.getenv("FASTAPI_SESSION_SECRET_KEY", "")

    @cached_property
    def fastapi_session_same_site(self) -> Literal["lax", "strict", "none"]:
        value = os.getenv("FASTAPI_SESSION_SAME_SITE", "none")
        if value in ("lax", "strict", "none"):
            return value
        raise InvalidEnvRuntimeErrorVo("FASTAPI_SESSION_SAME_SITE", value)

    # Kafka
    @cached_property
    def kafka_1_host(self) -> str:
        return self._getenv_or_getdotenv("KAFKA_1_HOST")

    @cached_property
    def kafka_1_plaintext_port(self) -> int:
        return int(self._getenv_or_getdotenv("KAFKA_1_PLAINTEXT_PORT"))

    @cached_property
    def kafka_2_host(self) -> str:
        return self._getenv_or_getdotenv("KAFKA_2_HOST")

    @cached_property
    def kafka_2_plaintext_port(self) -> int:
        return int(self._getenv_or_getdotenv("KAFKA_2_PLAINTEXT_PORT"))

    @cached_property
    def kafka_3_host(self) -> str:
        return self._getenv_or_getdotenv("KAFKA_3_HOST")

    @cached_property
    def kafka_3_plaintext_port(self) -> int:
        return int(self._getenv_or_getdotenv("KAFKA_3_PLAINTEXT_PORT"))

    def _getenv_or_getdotenv(self, key: str) -> str:
        if value := os.getenv(key):
            return value
        if self.dotenv_path and (value := get_key(self.dotenv_path, key)):
            return value
        raise MissingEnvRuntimeErrorVo(key)


impl = EnvsConf()
