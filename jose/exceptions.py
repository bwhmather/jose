class Error(Exception):
    """ The base error type raised by jose
    """
    pass


class Expired(Error):
    """ Raised during claims validation if a JWT has expired
    """
    pass


class NotYetValid(Error):
    """ Raised during claims validation is a JWT is not yet valid
    """
    pass
