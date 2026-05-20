from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter
from src._modules._healthcheck import healthcheck_svc

from src._confs._fastapi._api.api_dependencies_ctrl import APIDependenciesCtrl


@dataclass(frozen=True)
class HealthcheckCtrl(APIDependenciesCtrl):
    healthcheck_svc: healthcheck_svc.HealthcheckSvc = healthcheck_svc.impl

    def set_routes(self, router: APIRouter) -> None:
        @router.get("/healthcheck")
        def _() -> None:
            return self.healthcheck_svc.healthcheck_or_raise()


impl = HealthcheckCtrl()
