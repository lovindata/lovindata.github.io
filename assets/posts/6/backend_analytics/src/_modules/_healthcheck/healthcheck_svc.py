from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from src._confs._kafka import kafka_conf


@dataclass(frozen=True)
class HealthcheckSvc:
    kafka_conf: kafka_conf.KafkaConf = kafka_conf.impl

    def healthcheck_or_raise(self) -> None:
        try:
            self.kafka_conf.ping()
        except Exception:
            logger.error("Error during healthcheck.")
            raise


impl = HealthcheckSvc()
