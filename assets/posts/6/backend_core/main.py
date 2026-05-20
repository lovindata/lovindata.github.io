from threading import Thread

from loguru import logger
from watchfiles import run_process

from src._confs import loguru_conf
from src._confs._envs import envs_conf
from src._confs._fastapi import fastapi_conf
from src._confs._kafka import kafka_conf
from src._modules._ledger import ledger_svc
from src._modules._notifications import notifications_svc


def start() -> None:
    logger.info("Booting up... Getting everything ready!")
    loguru_conf.impl.set_log_level()
    Thread(
        target=kafka_conf.impl.subscribe,
        args=(
            "notifications-service",
            "payment.events",
            notifications_svc.impl.handle_payment_events,
        ),
        daemon=True,
    ).start()
    Thread(
        target=kafka_conf.impl.subscribe,
        args=(
            "ledger-service",
            "payment.events",
            ledger_svc.impl.handle_payment_events,
        ),
        daemon=True,
    ).start()
    fastapi_conf.impl.run_server()


@logger.catch
def main() -> None:
    if envs_conf.impl.watchfiles:
        run_process(
            "./src",
            "./main.py",
            envs_conf.impl.dotenv_path,
            target=start,
            args=(),
        )
    else:
        start()


if __name__ == "__main__":
    main()
