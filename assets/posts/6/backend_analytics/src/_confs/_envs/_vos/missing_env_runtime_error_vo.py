class MissingEnvRuntimeErrorVo(RuntimeError):
    def __init__(self, key: str) -> None:
        super().__init__(f"Not set {key}")
