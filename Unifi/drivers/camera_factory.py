from __future__ import annotations

from typing import Any, Dict, Type

from Unifi.drivers.camera_driver import CameraDriver
from Unifi.drivers.amcrest import AmcrestDriver
from Unifi.drivers.null import NullDriver

DRIVER_REGISTRY: Dict[str, Type[CameraDriver]] = {
    "amcrest": AmcrestDriver,
    "null": NullDriver,
}


def register_camera_driver(name: str, driver_cls: Type[CameraDriver]) -> None:
    DRIVER_REGISTRY[name.lower()] = driver_cls


def _resolve_settings(brand: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    if brand == "amcrest":
        return settings.get("amcrest", settings)
    return settings


def build_camera_driver(settings: Dict[str, Any], log) -> CameraDriver:
    brand = (settings.get("camera.type") or settings.get("camera_type") or "null").lower()
    driver_cls = DRIVER_REGISTRY.get(brand, NullDriver)
    driver_settings = _resolve_settings(brand, settings)
    return driver_cls(driver_settings, log)
