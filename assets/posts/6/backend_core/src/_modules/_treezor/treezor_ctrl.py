from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter

from src._confs._fastapi._api.api_dependencies_ctrl import APIDependenciesCtrl
from src._modules._treezor import treezor_svc
from src._modules._treezor._vos.treezor_webhook_vo import TreezorWebhookVo


@dataclass(frozen=True)
class TreezorCtrl(APIDependenciesCtrl):
    treezor_svc: treezor_svc.TreezorSvc = treezor_svc.impl

    def set_routes(self, router: APIRouter) -> None:
        @router.post("/treezor/webhook")
        def _(treezor_webhook: TreezorWebhookVo) -> None:
            self.treezor_svc.handle_webhook(treezor_webhook)


impl = TreezorCtrl()
