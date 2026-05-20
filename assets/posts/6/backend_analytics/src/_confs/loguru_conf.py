from __future__ import annotations

import sys
from dataclasses import dataclass

from loguru import logger

from src._confs._envs import envs_conf


@dataclass(frozen=True)
class LoguruConf:
    envs_conf: envs_conf.EnvsConf = envs_conf.impl

    def set_log_level(self) -> None:
        logger.remove()
        logger.add(sys.stderr, level=self.envs_conf.log_level.upper())


impl = LoguruConf()
