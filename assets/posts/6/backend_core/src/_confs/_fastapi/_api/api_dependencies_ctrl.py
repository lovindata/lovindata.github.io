from __future__ import annotations

from dataclasses import dataclass

from src._confs._fastapi._api.api_ctrl import APICtrl


@dataclass(frozen=True)
class APIDependenciesCtrl(APICtrl):
    # Depends
    ...
