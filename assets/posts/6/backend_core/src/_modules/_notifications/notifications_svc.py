from __future__ import annotations

import random
from dataclasses import dataclass

from loguru import logger

from src._confs._kafka._vos.value_vo import ValueVo
from src._modules._treezor._vos.treezor_webhook_vo import TreezorWebhookVo


@dataclass(frozen=True)
class NotificationsSvc:
    def handle_payment_events(self, value: ValueVo) -> None:
        # Simulation of a failure
        if random.random() < 0.1:
            raise RuntimeError("Notification delivery failed.")
        treezor_webhook = TreezorWebhookVo.model_validate(value)
        cardtransactions = treezor_webhook.object_payload.get("cardtransactions", [{}])[
            0
        ]
        # Send notifications
        # ...
        logger.info(
            "Notification sent successfully to buyer: amount={} {} at {} — {} on {}",
            cardtransactions.get("amount"),
            cardtransactions.get("currency"),
            cardtransactions.get("merchantName"),
            cardtransactions.get("cardtransactionStatus"),
            cardtransactions.get("createdDate"),
        )


impl = NotificationsSvc()
