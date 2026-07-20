class PaymentChallengeError(Exception): pass
class NoValidPaymentChallengeError(PaymentChallengeError): pass
class PaymentExecutionError(Exception): pass
class NavigationGuardrailError(Exception): pass
class InvoiceParseError(Exception): pass
# --- v1.4: Trust Layer ---
class CounterpartyTrustError(PaymentExecutionError): pass
