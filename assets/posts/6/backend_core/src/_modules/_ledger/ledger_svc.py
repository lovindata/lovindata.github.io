from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from src._confs._kafka._vos.value_vo import ValueVo
from src._modules._treezor._vos.treezor_webhook_vo import TreezorWebhookVo


@dataclass(frozen=True)
class LedgerSvc:
    def handle_payment_events(self, value: ValueVo) -> None:
        treezor_webhook = TreezorWebhookVo.model_validate(value)
        cardtransactions = treezor_webhook.object_payload.get("cardtransactions", [{}])[
            0
        ]
        # Save to ledger
        # ...
        logger.info(
            "Transaction saved to ledger: transaction_id={} amount={} {} merchant={} status={}",
            cardtransactions.get("cardtransactionId"),
            cardtransactions.get("amount"),
            cardtransactions.get("currency"),
            cardtransactions.get("merchantName"),
            cardtransactions.get("cardtransactionStatus"),
        )


impl = LedgerSvc()
