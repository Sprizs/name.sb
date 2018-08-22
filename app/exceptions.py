class AuthenticationError(Exception):pass
class ObjectNotFoundError(Exception):pass
class SessionError(Exception):pass
class WithMessageError(Exception):
    def __init__(self,msg):
        self.message=msg
class InputValidationError(WithMessageError):
    return_code=400
class ServerError(WithMessageError):
    return_code=500