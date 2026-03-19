from .client import LnChurchClient
from .models import AssetType

# --- 402 Client Abstraction Aliases ---
# 外部の開発者やAIには、こちらの汎用的な名前を使わせます
Payment402Client = LnChurchClient
Http402Client = LnChurchClient 

__all__ = ["LnChurchClient", "Payment402Client", "Http402Client", "AssetType"]