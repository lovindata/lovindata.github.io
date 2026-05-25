from __future__ import annotations

import base64
import os
import random
import time
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class TreezorWebhookVo(BaseModel):
    webhook: str = Field(
        examples=["cardtransaction.create"],
    )
    webhook_id: str = Field(
        examples=[str(uuid4())],
    )
    webhook_created_at: int = Field(
        examples=[int(time.time() * 10000)],
    )
    object: str = Field(
        examples=["cardtransaction"],
    )
    object_id: str = Field(
        examples=["190314"],
    )
    object_payload: Any = Field(
        examples=[
            {
                "cardtransactions": [
                    {
                        "cardtransactionId": "700013016",
                        "cardId": str(random.randint(1000000, 9999999)),
                        "amount": "15.00",
                        "currency": "EUR",
                        "cardtransactionStatus": "VALIDATED",
                        "merchantName": "SNCF Automate",
                        "merchantCountry": "FR",
                        "codeStatus": "170006",
                        "createdDate": "2024-11-07 14:30:00",
                    }
                ]
            }
        ],
    )
    object_payload_signature: str = Field(
        examples=[base64.b64encode(os.urandom(32)).decode()],
    )
