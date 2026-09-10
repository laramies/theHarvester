import random


def get_delay() -> float:
    """Return a random delay between 0.5 and 2.5 seconds."""
    return random.randint(1, 3) - 0.5


class MissingKeyError(Exception):
    """Raised when a discovery source is missing required credentials."""

    def __init__(self, source: str | None) -> None:
        if source:
            self.message = f'\n[!] Missing API key for {source}. '
        else:
            self.message = '\n[!] Missing CSE id. '

    def __str__(self) -> str:
        return self.message


# Backward compatibility: keep old name for external imports
MissingKey = MissingKeyError
