class PaymentChallengeError(Exception): pass
class NoValidPaymentChallengeError(PaymentChallengeError): pass
class PaymentExecutionError(Exception):
    def __init__(self, message, *, status_code=None, code=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code

class NavigationGuardrailError(Exception): pass
class InvoiceParseError(Exception): pass
# --- v1.4: Trust Layer ---
class CounterpartyTrustError(PaymentExecutionError): pass
