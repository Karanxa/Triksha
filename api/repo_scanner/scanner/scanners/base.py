from abc import ABC, abstractmethod
from typing import List
from ..result import Indicator

class BaseScanner(ABC):
    @abstractmethod
    def scan(self, file_path: str, content: str) -> List[Indicator]:
        """Scans a single file and returns a list of indicators found."""
        pass
