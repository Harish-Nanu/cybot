from cybot.intel.providers.base import IntelProvider, is_public_ip
from cybot.intel.providers.local import LocalIntelProvider
from cybot.intel.providers.remote import (
    AbuseIPDBProvider,
    GreyNoiseProvider,
    URLhausProvider,
    VirusTotalProvider,
)

__all__ = [
    "AbuseIPDBProvider",
    "GreyNoiseProvider",
    "IntelProvider",
    "LocalIntelProvider",
    "URLhausProvider",
    "VirusTotalProvider",
    "build_providers",
    "is_public_ip",
]


def build_providers(settings) -> list[IntelProvider]:
    """Local intel if its file exists, plus every remote service with an API key."""
    providers: list[IntelProvider] = []
    if settings.intel_local_path and settings.intel_local_path.is_file():
        providers.append(LocalIntelProvider(settings.intel_local_path))
    remote = (
        (settings.abuseipdb_api_key, AbuseIPDBProvider),
        (settings.virustotal_api_key, VirusTotalProvider),
        (settings.greynoise_api_key, GreyNoiseProvider),
        (settings.urlhaus_api_key, URLhausProvider),
    )
    for key, cls in remote:
        if key is not None and key.get_secret_value():
            providers.append(cls(key.get_secret_value(), timeout=settings.intel_timeout_seconds))
    return providers
