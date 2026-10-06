"""
NetSecureX MTA Scanner Gateway - Service Entrypoint.
Starts either the aiosmtpd proxy or pymilter service according to configuration.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

from netsecurex.config import load_config
from netsecurex.db.storage import DatabaseStorage
from netsecurex.milter.handler import run_milter_service
from netsecurex.proxy.smtp_proxy import create_smtp_proxy_controller
from netsecurex.scanners.engine import ScanEngine
from netsecurex.utils.logger import setup_logger


def main() -> None:
    parser = argparse.ArgumentParser(description="NetSecureX In-Transit Email Threat Scanner")
    parser.add_argument("-c", "--config", help="Path to YAML configuration file", default=None)
    parser.add_argument("-m", "--mode", choices=["proxy", "milter"], help="Override server mode (proxy or milter)")
    parser.add_argument("-p", "--port", type=int, help="Override listening port for proxy mode")
    parser.add_argument("--db", help="Override database connection URL")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    if args.mode:
        config.server.mode = args.mode
    if args.port:
        config.server.port = args.port
    if args.db:
        config.database.url = args.db

    # Setup logger
    logger = setup_logger(
        name="netsecurex",
        level=config.logging.level,
        log_format=config.logging.format,
        log_file=config.logging.log_file,
    )

    logger.info("=" * 60)
    logger.info(" NetSecureX MTA Email Scanning Gateway v1.0.0")
    logger.info("=" * 60)
    logger.info(f" Operating Mode: {config.server.mode.upper()}")
    logger.info(f" Database URL:   {config.database.url}")
    logger.info(f" Thresholds:     Medium={config.decision_engine.medium_risk_threshold}, High={config.decision_engine.high_risk_threshold}")
    logger.info(f" High Risk Act:  {config.decision_engine.high_risk_action.upper()}")

    # Initialize Database and Scan Engine
    storage = DatabaseStorage(db_url=config.database.url, echo=config.database.echo)
    engine = ScanEngine(config=config, storage=storage)

    if config.server.mode.lower() == "milter":
        logger.info(f" Starting Milter listener on {config.server.milter_socket}...")
        try:
            run_milter_service(engine=engine, config=config)
        except Exception as e:
            logger.error(f"Failed to start Milter service: {e}")
            sys.exit(1)
    else:
        # Proxy Mode (aiosmtpd)
        host = config.server.host
        port = config.server.port
        downstream = f"{config.server.downstream_host}:{config.server.downstream_port}"
        logger.info(f" Starting SMTP Proxy on {host}:{port} -> Forwarding to {downstream}...")

        controller = create_smtp_proxy_controller(engine=engine, config=config)
        controller.start()
        logger.info(f" NetSecureX Gateway is active and intercepting SMTP traffic on port {port}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Handle termination signals
        stop_event = asyncio.Event()

        def _handle_signal(*_):
            logger.info("Shutdown signal received. Stopping gateway...")
            stop_event.set()

        try:
            signal.signal(signal.SIGINT, _handle_signal)
            signal.signal(signal.SIGTERM, _handle_signal)
        except (ValueError, AttributeError):
            pass  # Windows signal limitations

        async def _wait_for_stop():
            while not stop_event.is_set():
                await asyncio.sleep(0.5)

        try:
            loop.run_until_complete(_wait_for_stop())
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received.")
        finally:
            logger.info("Stopping SMTP Controller...")
            controller.stop()
            logger.info("NetSecureX Gateway stopped gracefully.")


if __name__ == "__main__":
    main()
