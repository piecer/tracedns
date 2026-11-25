"""Closed observed HTTP rejection policy; not remote cancellation proof."""
from dataclasses import dataclass
from types import MappingProxyType

# The configured endpoint is trusted to honor these request-rejection statuses.
# Incomplete/late frames and other status codes cannot release a reservation.
HTTP_REJECTION_CODES = MappingProxyType({
    400: 'provider_request_rejected',
    401: 'provider_auth_failed',
    403: 'provider_auth_failed',
    404: 'provider_request_rejected',
    422: 'provider_request_rejected',
    429: 'provider_rate_limited',
})


@dataclass(frozen=True)
class ProviderRejected:
    """A complete bounded response; contains no model data or upstream body."""

    http_status: int

    def __post_init__(self):
        if type(self.http_status) is not int or self.http_status not in HTTP_REJECTION_CODES:
            raise ValueError('Invalid provider rejection')
