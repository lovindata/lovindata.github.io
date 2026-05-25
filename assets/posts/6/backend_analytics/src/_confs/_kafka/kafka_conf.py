from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cached_property
from typing import Callable

from confluent_kafka import Consumer, KafkaError, Message, Producer
from loguru import logger

from src._confs._envs import envs_conf
from src._confs._kafka._vos import group_id_vo, key_vo, topic_vo, value_vo


@dataclass(frozen=True)
class KafkaConf:
    envs_conf: envs_conf.EnvsConf = envs_conf.impl

    def ping(self) -> None:
        self._main_producer.list_topics(timeout=10)

    def produce(
        self,
        topic: topic_vo.TopicVo,
        value: value_vo.ValueVo,
        key: key_vo.KeyVo = None,
    ) -> None:
        self._main_producer.produce(
            topic,
            key=key.encode("utf-8") if key else None,
            value=json.dumps(value).encode("utf-8"),
            callback=self._produce_callback,
        )
        self._main_producer.flush()

    def subscribe(
        self,
        group_id: group_id_vo.GroupIdVo,
        topic: topic_vo.TopicVo,
        handler: Callable[[value_vo.ValueVo], None],
    ) -> None:
        consumer = self._create_consumer(group_id, topic)
        try:
            dlq_topic = f"{topic}.{group_id}.dlq"
            dlq_producer = self._create_producer()
            while True:
                message = consumer.poll(timeout=1.0)
                if message is None:
                    continue
                if kafka_error := message.error():
                    logger.error(
                        "Subscriber error on topic={} group_id={}: {}",
                        topic,
                        group_id,
                        kafka_error,
                    )
                    continue
                message_value = message.value()
                if message_value is None:
                    logger.error(
                        "Subscriber received empty message on topic={} group_id={}: value={}",
                        topic,
                        group_id,
                        message_value,
                    )
                    consumer.commit(message=message)
                    continue
                try:
                    event = json.loads(message_value.decode("utf-8"))
                    handler(event)
                    consumer.commit(message=message)
                except Exception:
                    logger.exception(
                        "Subscriber failed to handle event on topic={} group_id={}. Redirecting to DLQ topic={}.",
                        topic,
                        group_id,
                        dlq_topic,
                    )
                    try:
                        dlq_producer.produce(
                            dlq_topic,
                            value=message_value,
                            callback=self._produce_callback,
                        )
                        dlq_producer.flush()
                        consumer.commit(message=message)
                    except Exception:
                        logger.exception(
                            "DLQ produce failed for topic={} group_id={}. "
                            "Offset will not be committed — message will be re-delivered on next poll.",
                            topic,
                            group_id,
                        )
        finally:
            consumer.close()

    @cached_property
    def _main_producer(self) -> Producer:
        return self._create_producer()

    @cached_property
    def _kafka_bootstrap_servers(self) -> str:
        return ",".join(
            [
                f"{self.envs_conf.kafka_1_host}:{self.envs_conf.kafka_1_plaintext_port}",
                f"{self.envs_conf.kafka_2_host}:{self.envs_conf.kafka_2_plaintext_port}",
                f"{self.envs_conf.kafka_3_host}:{self.envs_conf.kafka_3_plaintext_port}",
            ]
        )

    def _create_producer(self) -> Producer:
        return Producer(
            {
                "bootstrap.servers": self._kafka_bootstrap_servers,
                "security.protocol": "PLAINTEXT",
            }
        )

    def _produce_callback(
        self,
        kafka_error: KafkaError | None,
        message: Message,
    ) -> None:
        if kafka_error:
            logger.error("Failed to push to topic={}: {}", message.topic(), kafka_error)
        else:
            logger.info(
                "Successfully pushed to topic={} (partition={}, offset={}).",
                message.topic(),
                message.partition(),
                message.offset(),
            )

    def _create_consumer(
        self,
        group_id: group_id_vo.GroupIdVo,
        topic: topic_vo.TopicVo,
    ) -> Consumer:
        consumer = Consumer(
            {
                "bootstrap.servers": self._kafka_bootstrap_servers,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
            }
        )
        consumer.subscribe([topic])
        logger.info(
            "Subscribed to {} (group.id={}).",
            topic,
            group_id,
        )
        return consumer


impl = KafkaConf()
