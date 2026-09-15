try:
    from src.threatfusion.engine import ENGINE_VERSION
except ImportError:
    from threatfusion.engine import ENGINE_VERSION

__version__ = ENGINE_VERSION
