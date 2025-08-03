import logging
import sys
import structlog


def configure_logging(log_file_path: str = None, log_level=logging.INFO):
    """Configures structlog for plain-text logging to both the console and an optional file."""

    # These processors run first to enrich the log event.
    pre_chain = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
        structlog.processors.format_exc_info,
    ]

    # This configures the standard logging handlers.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True),
            foreign_pre_chain=pre_chain,
        )
    )
    console_handler.setLevel(log_level)
    handlers = [console_handler]

    if log_file_path:
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.dev.ConsoleRenderer(colors=False),
                foreign_pre_chain=pre_chain,
            )
        )
        file_handler.setLevel(log_level)
        handlers.append(file_handler)

    logging.basicConfig(handlers=handlers, level=log_level)

    # These are the final processors that do the rest of the work.
    # They should NOT be in the 'pre_chain'.
    structlog.configure(
        processors=pre_chain
        + [
            structlog.processors.EventRenamer("message"),
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.LINENO,
                ]
            ),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
