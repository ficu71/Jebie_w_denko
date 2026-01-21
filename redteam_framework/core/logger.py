import logging
import sys
from pathlib import Path
from datetime import datetime

logger = logging.getLogger('ComprehensiveFramework')

def setup_logging(verbose: bool = True, log_level: str = "INFO"):
    """
    Configure the global logger.
    """
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"pentest_framework_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Reset handlers to avoid duplicates if called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if verbose:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    else:
        logger.addHandler(logging.NullHandler())
    
    logger.setLevel(level)
    return logger
