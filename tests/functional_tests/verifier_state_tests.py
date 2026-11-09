from __future__ import unicode_literals

import threading

import pytest
from nacl.exceptions import CryptoError

from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import (
    MacaroonAmbiguousDischargeException,
    MacaroonCyclicCaveatException,
    MacaroonInvalidSignatureException,
    MacaroonUnmetCaveatException,
)


def third_party_chain():
    """A root macaroon with one third-party caveat and its discharge."""
    root = Macaroon(location='', identifier='root-id', key='root-key')
    root.add_first_party_caveat('account = 1')
    root.add_third_party_caveat('loc-auth', 'auth-key', 'auth-id')
    discharge = Macaroon(location='loc-auth', identifier='auth-id',
                         key='auth-key')
    discharge.add_first_party_caveat('time < now')
    protected = root.prepare_for_request(discharge)
    return root, protected


def verifier_for(discharge, *predicates):
    verifier = Verifier(discharge_macaroons=[discharge])
    verifier.satisfy_exact('account = 1')
    for predicate in predicates:
        verifier.satisfy_exact(predicate)
    return verifier


def config_snapshot(verifier, macaroons):
    delegate = verifier.third_party_caveat_verifier_delegate
    return {
        'predicates': list(verifier.predicates),
        'callbacks': len(verifier.callbacks),
        'discharges': [m.signature for m in delegate.discharge_macaroons],
        'macaroons': [(m.signature, len(m.caveats)) for m in macaroons],
    }


class TestVerifierState(object):

    def test_verify_twice_with_same_verifier(self):
        root, discharge = third_party_chain()
        verifier = verifier_for(discharge, 'time < now')
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')

    def test_retry_after_invalid_signature(self):
        macaroon = Macaroon(location='', identifier='root-id',
                            key='root-key')
        macaroon.add_first_party_caveat('account = 1')
        verifier = Verifier()
        verifier.satisfy_exact('account = 1')
        before = config_snapshot(verifier, [macaroon])
        with pytest.raises(MacaroonInvalidSignatureException):
            verifier.verify(macaroon, 'wrong-key')
        assert verifier.verify(macaroon, 'root-key')
        assert verifier.verify(macaroon, 'root-key')
        assert config_snapshot(verifier, [macaroon]) == before

    def test_retry_after_failed_third_party_key_derivation(self):
        # a wrong root key surfaces as a decryption failure while
        # extracting the third-party caveat key; the verifier and the
        # macaroons must be left untouched
        root, discharge = third_party_chain()
        verifier = verifier_for(discharge, 'time < now')
        before = config_snapshot(verifier, [root, discharge])
        with pytest.raises(CryptoError):
            verifier.verify(root, 'wrong-key')
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')
        assert config_snapshot(verifier, [root, discharge]) == before

    def test_retry_after_unmet_caveat(self):
        root, discharge = third_party_chain()
        verifier = verifier_for(discharge)
        before = config_snapshot(verifier, [root, discharge])
        with pytest.raises(MacaroonInvalidSignatureException):
            verifier.verify(root, 'root-key')
        verifier.satisfy_exact('time < now')
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')
        after = config_snapshot(verifier, [root, discharge])
        after['predicates'].remove('time < now')
        assert after == before

    def test_retry_after_missing_discharge(self):
        root, discharge = third_party_chain()
        verifier = verifier_for(discharge, 'time < now')
        delegate = verifier.third_party_caveat_verifier_delegate
        configured = delegate.discharge_macaroons
        delegate.discharge_macaroons = []
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(root, 'root-key')
        delegate.discharge_macaroons = configured
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')

    def test_retry_after_callback_exception(self):
        root, discharge = third_party_chain()
        verifier = verifier_for(discharge, 'time < now')
        access_log = []
        failures = [1]

        def recording_callback(predicate):
            access_log.append(predicate)
            if failures:
                failures.pop()
                raise RuntimeError('callback blew up')
            return predicate in ('account = 1', 'time < now')

        verifier.callbacks = [recording_callback]
        with pytest.raises(RuntimeError):
            verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')
        # the callback actually ran for every caveat of every attempt:
        # the first attempt died on the first caveat, the retries visited
        # both the root and the discharge caveats
        assert access_log == [
            'account = 1',
            'account = 1', 'time < now',
            'account = 1', 'time < now',
        ]

    def test_diamond_dependency(self):
        root = Macaroon(location='', identifier='root-id', key='root-key')
        root.add_third_party_caveat('loc-a', 'key-a', 'id-a')
        root.add_third_party_caveat('loc-b', 'key-b', 'id-b')
        branch_a = Macaroon(location='loc-a', identifier='id-a', key='key-a')
        branch_a.add_third_party_caveat('loc-c', 'key-c', 'id-c')
        branch_b = Macaroon(location='loc-b', identifier='id-b', key='key-b')
        branch_b.add_third_party_caveat('loc-c', 'key-c', 'id-c')
        shared = Macaroon(location='loc-c', identifier='id-c', key='key-c')
        shared.add_first_party_caveat('c-ok = true')
        discharges = [
            root.prepare_for_request(m) for m in (branch_a, branch_b, shared)
        ]
        verifier = Verifier(discharge_macaroons=discharges)
        verifier.satisfy_exact('c-ok = true')
        # the shared discharge is used by both branches, and the verifier
        # remains reusable afterwards
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')

    def test_self_referencing_discharge_is_a_cycle(self):
        root = Macaroon(location='', identifier='root-id', key='root-key')
        root.add_third_party_caveat('loc-a', 'key-a', 'id-a')
        discharge = Macaroon(location='loc-a', identifier='id-a', key='key-a')
        discharge.add_third_party_caveat('loc-a', 'key-a', 'id-a')
        discharge = root.prepare_for_request(discharge)
        verifier = Verifier(discharge_macaroons=[discharge])
        with pytest.raises(MacaroonCyclicCaveatException):
            verifier.verify(root, 'root-key')
        # cyclic dependencies are also reported as unmet caveats
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(root, 'root-key')

    def test_mutual_discharge_cycle(self):
        root = Macaroon(location='', identifier='root-id', key='root-key')
        root.add_third_party_caveat('loc-a', 'key-a', 'id-a')
        discharge_a = Macaroon(location='loc-a', identifier='id-a',
                               key='key-a')
        discharge_a.add_third_party_caveat('loc-b', 'key-b', 'id-b')
        discharge_b = Macaroon(location='loc-b', identifier='id-b',
                               key='key-b')
        discharge_b.add_third_party_caveat('loc-a', 'key-a', 'id-a')
        discharges = [
            root.prepare_for_request(m) for m in (discharge_a, discharge_b)
        ]
        verifier = Verifier(discharge_macaroons=discharges)
        with pytest.raises(MacaroonCyclicCaveatException):
            verifier.verify(root, 'root-key')

    def test_ambiguous_identifier_is_rejected(self):
        root = Macaroon(location='', identifier='root-id', key='root-key')
        root.add_third_party_caveat('loc-a', 'key-a', 'id-a')
        first = Macaroon(location='loc-a', identifier='id-a', key='key-a')
        second = Macaroon(location='loc-a', identifier='id-a', key='key-a')
        second.add_first_party_caveat('different = content')
        discharges = [root.prepare_for_request(m) for m in (first, second)]
        verifier = Verifier(discharge_macaroons=discharges)
        verifier.satisfy_exact('different = content')
        with pytest.raises(MacaroonAmbiguousDischargeException):
            verifier.verify(root, 'root-key')

    def test_identical_discharges_are_deduplicated(self):
        root, discharge = third_party_chain()
        duplicate = Macaroon.deserialize(discharge.serialize())
        verifier = Verifier(discharge_macaroons=[discharge, duplicate])
        verifier.satisfy_exact('account = 1')
        verifier.satisfy_exact('time < now')
        assert verifier.verify(root, 'root-key')
        assert verifier.verify(root, 'root-key')

    def test_discharge_bound_to_another_root_is_rejected(self):
        root, _ = third_party_chain()
        other_root = Macaroon(location='', identifier='other-id',
                              key='other-key')
        other_root.add_third_party_caveat('loc-auth', 'auth-key', 'auth-id')
        foreign = Macaroon(location='loc-auth', identifier='auth-id',
                           key='auth-key')
        foreign.add_first_party_caveat('time < now')
        foreign = other_root.prepare_for_request(foreign)
        verifier = verifier_for(foreign, 'time < now')
        with pytest.raises(MacaroonInvalidSignatureException):
            verifier.verify(root, 'root-key')
        # sanity check: the same discharge is valid for its own root
        other = Verifier(discharge_macaroons=[foreign])
        other.satisfy_exact('time < now')
        assert other.verify(other_root, 'other-key')

    def test_interleaved_verifications_do_not_consume_discharges(self):
        root, discharge = third_party_chain()
        verifier = verifier_for(discharge, 'time < now')
        access_log = []
        log_lock = threading.Lock()
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def recording_callback(predicate):
            with log_lock:
                access_log.append((threading.current_thread().name,
                                   predicate))
            try:
                barrier.wait(timeout=10)
            except threading.BrokenBarrierError:
                pass
            return predicate in ('account = 1', 'time < now')

        verifier.callbacks = [recording_callback]

        def worker():
            try:
                results.append(verifier.verify(root, 'root-key'))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        assert results == [True, True]
        # both threads really visited both caveats through the callback
        assert len(access_log) == 4
        # and the verifier is still usable afterwards
        verifier.callbacks = [verifier.verify_exact]
        assert verifier.verify(root, 'root-key')
        assert len(access_log) == 4
