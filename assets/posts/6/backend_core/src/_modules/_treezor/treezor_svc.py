from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from loguru import logger

from src._confs._kafka import kafka_conf
from src._modules._treezor._vos.treezor_webhook_vo import TreezorWebhookVo


@dataclass(frozen=True)
class TreezorSvc:
    kafka_conf: kafka_conf.KafkaConf = kafka_conf.impl

    def handle_webhook(self, treezor_webhook: TreezorWebhookVo) -> None:
        self._validate_signature(treezor_webhook)
        key: str | None = None
        if (
            (
                cardtransactions := treezor_webhook.object_payload.get(
                    "cardtransactions", []
                )
            )
            and cardtransactions
            and (cardtransaction := cardtransactions[0])
            and isinstance(cardtransaction, dict)
            and (card_id := cardtransaction.get("cardId"))
            and isinstance(card_id, str)
        ):
            key = card_id
        self.kafka_conf.produce(
            "payment.events",
            treezor_webhook.model_dump(),
            key=key,
        )

    def _validate_signature(self, treezor_webhook: TreezorWebhookVo) -> None:
        # Validation
        # ...
        logger.info(
            "Signature validated for webhook_id={} event={} object_id={}",
            treezor_webhook.webhook_id,
            treezor_webhook.webhook,
            treezor_webhook.object_id,
        )


impl = TreezorSvc()
