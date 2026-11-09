from contextlib import contextmanager

from pymacaroons.exceptions import (
    MacaroonAmbiguousDischargeException,
    MacaroonCyclicCaveatException,
)


class VerificationContext(object):
    """State that belongs to a single verification run.

    A Verifier's configuration (predicates, callbacks and the discharge
    macaroons held by its delegates) is shared, read-only state. Everything
    that is consumed or tracked while walking the third-party caveat
    dependency graph lives here instead, so:

    - a Verifier can be reused for any number of verify() calls,
    - concurrent verify() calls (each with its own context) do not
      interfere with one another,
    - a failed or aborted run leaves no residue behind.

    The context tracks two things:

    - resolved discharges: per-identifier resolution of the configured
      discharge macaroons, deduplicating identical candidates and
      rejecting ambiguous ones,
    - the current discharge path: the chain of third-party caveats
      currently being discharged, used to reject cyclic dependencies
      without unbounded recursion.
    """

    def __init__(self, root):
        self.root = root
        self._discharge_path = []
        self._resolved_discharges = {}

    def resolve_discharge(self, identifier, candidates):
        """Resolve the discharge macaroon for a third-party caveat id.

        Identical candidates (same identifier and signature) are
        deduplicated; distinct candidates for the same identifier are
        ambiguous and rejected explicitly. Returns None when no candidate
        matches. The result is memoized for the duration of this run.
        """
        if identifier in self._resolved_discharges:
            return self._resolved_discharges[identifier]
        distinct = {}
        for candidate in candidates or []:
            if candidate.identifier_bytes != identifier:
                continue
            key = (candidate.identifier_bytes, candidate.signature_bytes)
            distinct.setdefault(key, candidate)
        if len(distinct) > 1:
            raise MacaroonAmbiguousDischargeException(
                'Multiple distinct discharge macaroons found for '
                'identifier: {}'.format(identifier)
            )
        resolved = next(iter(distinct.values()), None)
        self._resolved_discharges[identifier] = resolved
        return resolved

    @contextmanager
    def discharging(self, identifier):
        """Mark a discharge as on the current verification path.

        Re-entering the same identifier while it is still on the path
        means the third-party caveats form a cycle and is rejected.
        """
        if identifier in self._discharge_path:
            raise MacaroonCyclicCaveatException(
                'Cyclic third-party caveat dependency detected for '
                'identifier: {}'.format(identifier)
            )
        self._discharge_path.append(identifier)
        try:
            yield
        finally:
            self._discharge_path.pop()
