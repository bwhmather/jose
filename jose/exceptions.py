class Error(Exception):
    """ The base error type raised by jose
    """
    pass


class TimingError(Error):
    """ Raised if JWT is not valid at the requested time
    """
    pass


class Expired(TimingError):
    """ Raised during claims validation if a JWT has expired
    """
    pass


class NotYetValid(TimingError):
    """ Raised during claims validation is a JWT is not yet valid
    """
    pass
