from __future__ import unicode_literals
import binascii

from nacl.secret import SecretBox

from pymacaroons import Caveat
from pymacaroons.utils import (
    convert_to_bytes,
    truncate_or_pad,
    generate_derived_key,
    sign_third_party_caveat,
)
from pymacaroons.exceptions import MacaroonUnmetCaveatException
from pymacaroons.verification_context import VerificationContext
from .base_third_party import (
    BaseThirdPartyCaveatDelegate,
    BaseThirdPartyCaveatVerifierDelegate,
)


class ThirdPartyCaveatDelegate(BaseThirdPartyCaveatDelegate):

    def __init__(self, *args, **kwargs):
        super(ThirdPartyCaveatDelegate, self).__init__(*args, **kwargs)

    def add_third_party_caveat(self,
                               macaroon,
                               location,
                               key,
                               key_id,
                               **kwargs):
        derived_key = truncate_or_pad(
            generate_derived_key(convert_to_bytes(key))
        )
        old_key = truncate_or_pad(binascii.unhexlify(macaroon.signature_bytes))
        box = SecretBox(key=old_key)
        verification_key_id = box.encrypt(
            derived_key, nonce=kwargs.get('nonce')
        )
        caveat = Caveat(
            caveat_id=key_id,
            location=location,
            verification_key_id=verification_key_id,
            version=macaroon.version
        )
        macaroon.caveats.append(caveat)
        encode_key = binascii.unhexlify(macaroon.signature_bytes)
        macaroon.signature = sign_third_party_caveat(
            encode_key,
            caveat._verification_key_id,
            caveat._caveat_id
        )
        return macaroon


class ThirdPartyCaveatVerifierDelegate(BaseThirdPartyCaveatVerifierDelegate):

    def __init__(self, discharge_macaroons=None, *args, **kwargs):
        super(ThirdPartyCaveatVerifierDelegate, self).__init__(*args, **kwargs)
        # Shared, read-only configuration. Discharges are never consumed
        # or removed during verification; per-run state lives in the
        # VerificationContext passed to verify_third_party_caveat().
        self.discharge_macaroons = list(discharge_macaroons or [])

    def verify_third_party_caveat(self,
                                  verifier,
                                  caveat,
                                  root,
                                  macaroon,
                                  signature,
                                  context=None):
        if context is None:
            context = VerificationContext(root)
        caveat_macaroon = self._caveat_macaroon(caveat, context)
        caveat_key = self._extract_caveat_key(signature, caveat)

        with context.discharging(caveat.caveat_id_bytes):
            return verifier.verify_discharge(
                root,
                caveat_macaroon,
                caveat_key,
                context=context,
            )

    def update_signature(self, signature, caveat):
        return binascii.unhexlify(
            sign_third_party_caveat(
                signature,
                caveat._verification_key_id,
                caveat._caveat_id
            )
        )

    def _caveat_macaroon(self, caveat, context):
        caveat_macaroon = context.resolve_discharge(
            caveat.caveat_id_bytes,
            self._configured_discharges(),
        )

        if not caveat_macaroon:
            raise MacaroonUnmetCaveatException(
                'Caveat not met. No discharge macaroon found for identifier: '
                '{}'.format(caveat.caveat_id_bytes)
            )

        return caveat_macaroon

    def _configured_discharges(self):
        configured = self.discharge_macaroons
        if isinstance(configured, dict):
            # Tolerate the pre-context dict layout if assigned directly.
            return list(configured.values())
        return configured

    def _extract_caveat_key(self, signature, caveat):
        key = truncate_or_pad(signature)
        box = SecretBox(key=key)
        decrypted = box.decrypt(caveat._verification_key_id)
        return decrypted
