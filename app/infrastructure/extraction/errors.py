class ExtractionError(Exception):
    """Raised when firmware extraction cannot be completed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
