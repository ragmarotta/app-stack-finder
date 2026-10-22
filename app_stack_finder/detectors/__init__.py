"""Detection modules registry."""

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.detectors.header_detector import HeaderDetector
from app_stack_finder.detectors.infra_detector import InfraDetector
from app_stack_finder.detectors.manifest_detector import ManifestDetector

DEFAULT_DETECTORS = [
    ManifestDetector(),
    InfraDetector(),
    HeaderDetector(),
]

__all__ = [
    "BaseDetector",
    "ManifestDetector",
    "InfraDetector",
    "HeaderDetector",
    "DEFAULT_DETECTORS",
]
