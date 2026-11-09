from abc import ABCMeta, abstractmethod


class BaseThirdPartyCaveatDelegate(object):
    __metaclass__ = ABCMeta

    def __init__(self, *args, **kwargs):
        super(BaseThirdPartyCaveatDelegate, self).__init__(*args, **kwargs)

    @abstractmethod
    def add_third_party_caveat(self,
                               macaroon,
                               location,
                               key,
                               key_id,
                               **kwargs):
        pass


class BaseThirdPartyCaveatVerifierDelegate(object):
    __metaclass__ = ABCMeta

    def __init__(self, *args, **kwargs):
        super(BaseThirdPartyCaveatVerifierDelegate, self).__init__(
            *args, **kwargs
        )

    @abstractmethod
    def verify_third_party_caveat(self,
                                  verifier,
                                  caveat,
                                  root,
                                  macaroon,
                                  signature,
                                  context=None):
        """Verify a third-party caveat.

        Compatibility boundary: Verifier always passes a per-verification
        VerificationContext as the context keyword argument. Custom
        verifier delegates must accept it (or **kwargs) and forward it to
        any nested verifier.verify_discharge(...) call so that discharge
        resolution, cycle detection and deduplication stay scoped to a
        single verification run. The context is scratch space for the
        current run only; verifier configuration and macaroons must not
        be mutated.
        """
        pass

    @abstractmethod
    def update_signature(self, signature, caveat):
        pass
