from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from src._confs._kafka._vos.value_vo import ValueVo
from src._modules._treezor._vos.treezor_webhook_vo import TreezorWebhookVo


@dataclass(frozen=True)
class AnalyticsSvc:
    def handle_payment_events(self, value: ValueVo) -> None:
        treezor_webhook = TreezorWebhookVo.model_validate(value)
        cardtransactions = treezor_webhook.object_payload.get("cardtransactions", [{}])[
            0
        ]
        # Push to analytics service
        # ...
        logger.info(
            "Analytics event processed: transaction_id={} card_id={} amount={} {} status={}",
            cardtransactions.get("cardtransactionId"),
            cardtransactions.get("cardId"),
            cardtransactions.get("amount"),
            cardtransactions.get("currency"),
            cardtransactions.get("cardtransactionStatus"),
        )


impl = AnalyticsSvc()
