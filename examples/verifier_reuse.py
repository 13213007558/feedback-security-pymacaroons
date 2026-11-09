"""Reusing one Verifier across many verifications.

Demonstrates the boundary between shared configuration and per-run state:

- shared, read-only configuration: the verifier's exact predicates,
  general callbacks and the discharge macaroons held by its third-party
  caveat delegate,
- per-run state: discharge resolution and cycle detection, which live in
  a fresh VerificationContext created by every verify() call.

Because nothing is consumed or mutated, the same verifier verifies the
same macaroon twice (or any number of times, from any number of threads,
as long as the configuration is not modified mid-flight).

Run with: python examples/verifier_reuse.py
"""

from pymacaroons import Macaroon, Verifier

# --- one-time credential setup (all keys generated locally) -------------

root = Macaroon(location='https://api.example.com',
                identifier='user-42-session',
                key='target-service-secret')
root.add_first_party_caveat('action = read')
root.add_third_party_caveat('https://auth.example.com',
                            'auth-service-secret',
                            'auth-ticket-7')

discharge = Macaroon(location='https://auth.example.com',
                     identifier='auth-ticket-7',
                     key='auth-service-secret')
discharge.add_first_party_caveat('mfa = passed')
discharge = root.prepare_for_request(discharge)

# --- shared verifier configuration --------------------------------------

verifier = Verifier(discharge_macaroons=[discharge])
verifier.satisfy_exact('action = read')
verifier.satisfy_exact('mfa = passed')

# --- repeated verification with the same verifier ------------------------

first = verifier.verify(root, 'target-service-secret')
second = verifier.verify(root, 'target-service-secret')

print('first verify: ', first)
print('second verify:', second)
assert first and second
