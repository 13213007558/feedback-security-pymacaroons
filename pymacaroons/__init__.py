from .caveat import Caveat
from .macaroon import Macaroon
from .macaroon import MACAROON_V1
from .macaroon import MACAROON_V2
from .verifier import Verifier
from .verification_context import VerificationContext


__all__ = [
    'Macaroon',
    'Caveat',
    'Verifier',
    'VerificationContext',
    'MACAROON_V1',
    'MACAROON_V2'
]


__author__ = 'Evan Cordell'

__version__ = "0.13.0"
__version_info__ = tuple(__version__.split('.'))
__short_version__ = __version__
