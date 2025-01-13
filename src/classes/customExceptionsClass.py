from utils import *

# custom base class for exceptions
class CustomExceptions(BaseException):

    msg: Optional[str] = None
    sup_kwargs: Set[str] = set()
    fmt: Optional[str] = None

    def __init__(self, *args, **kwargs) -> NoReturn:
        self._check_params(*args, **kwargs)
        if kwargs:
            # This call to a virtual method from __init__ is ok in our usage
            self.kwargs = self._check_kwargs(**kwargs)
            self.msg = str(self)
        else:
            self.kwargs = dict()  # defined but empty
        if self.msg is None:
            # doc string is better implicit message than empty string
            self.msg = self.__doc__
        if args:
            super().__init__(*args)
        else:
            super().__init__(self.msg)

    def _check_params(self, *args, **kwargs):
        """supp for both args and kwargs.
           but not mixing them
        """
        if args or kwargs:
            assert bool(args) != bool(
                kwargs
            ), "keyword arguments are mutually exclusive with positional args"

    def _check_kwargs(self, **kwargs) -> list[dict]:
        if kwargs:
            assert (
                set(kwargs.keys()) == self.sup_kwargs
            ), f"following set of keyword args is required: {self.sup_kwargs}"
        return kwargs

    def _fmt_kwargs(self, **kwargs) -> list[dict]:
        """Format kwargs before printing them.

        Resulting dictionary has to have keys necessary for str.format call
        on fmt class variable.
        """
        fmtargs = {}
        for kw, data in kwargs.items():
            if isinstance(data, (list, set)):
                # convert list of <someobj> to list of str(<someobj>)
                fmtargs[kw] = list(map(str, data))
                if len(fmtargs[kw]) == 1:
                    # remove list brackets [] from single-item lists
                    fmtargs[kw] = fmtargs[kw].pop()
            else:
                fmtargs[kw] = data
        return fmtargs

    def __str__(self) -> str:
        if self.kwargs and self.fmt:
            # provide custom message constructed from keyword arguments
            fmtargs = self._fmt_kwargs(**self.kwargs)
            return self.fmt.format(**fmtargs)
        else:
            # print *args directly
            return super().__str__()

# Creating custom exceptions
class WrongPayloadError(CustomExceptions):
    sup_kwargs = {"errC"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class UnkownPacketError(CustomExceptions):
    sup_kwargs = {"errC"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class NoIpProvidedError(CustomExceptions):
    sup_kwargs = {"errC"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class GatewayFindError(CustomExceptions):
    sup_kwargs = {"errC"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class PrvIpFindError(CustomExceptions):
    sup_kwargs = {"errC"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class UnsupportedProtocolError(CustomExceptions):
    sup_kwargs = {"errC"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

