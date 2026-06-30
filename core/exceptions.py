class ReconError(Exception):
    """Base exception for RECON."""
    pass


class ResolutionError(ReconError):
    """Raised when target resolution fails."""
    pass