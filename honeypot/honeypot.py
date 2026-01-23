#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import time

LOG_PATH = "/app/logs/honeypot.log"


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )


def run_honeypot():
    logger = logging.getLogger("Honeypot")
    logger.info("Honeypot starter template running.")
    logger.info("TODO: Implement protocol simulation, logging, and alerting.")

    while True:
        time.sleep(60)


if __name__ == "__main__":
    setup_logging()
    run_honeypot()
