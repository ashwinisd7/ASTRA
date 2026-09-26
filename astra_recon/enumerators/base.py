from abc import ABC, abstractmethod
from typing import List, Dict, Any
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class BaseEnumerator(ABC):
    """Abstract base class for all WordPress user enumeration vectors."""

    name: str = "base_technique"
    description: str = "Base description of enumeration technique."

    @abstractmethod
    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        """
        Executes the enumeration probe against the target WordPress site.
        
        Args:
            target_url: Base target URL (e.g. http://localhost:8080)
            client: Resilient HTTP client
            context: Shared scan context / state from previous steps
            
        Returns:
            List of DiscoveredUser objects
        """
        pass
