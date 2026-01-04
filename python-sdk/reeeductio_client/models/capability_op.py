from enum import Enum

class CapabilityOp(str, Enum):
    CREATE = "create"
    READ = "read"
    WRITE = "write"

    def __str__(self) -> str:
        return str(self.value)
