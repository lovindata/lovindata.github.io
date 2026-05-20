from typing import Any


class InvalidEnvRuntimeErrorVo(RuntimeError):
    def __init__(self, key: str, value: Any) -> None:
        super().__init__(f"Invalid {key}" + f": {value}")
