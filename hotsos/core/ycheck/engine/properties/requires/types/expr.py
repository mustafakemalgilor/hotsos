import os
from abc import abstractmethod
from typing import Callable, Iterable

import pyparsing as pp
# from hotsos.core.log import log
from hotsos.core.ycheck.engine.properties.common import (
    PythonEntityResolver
)
from hotsos.core.ycheck.engine.properties.requires import (
    intercept_exception,
    YRequirementTypeWithOpsBase,
)
from hotsos.core.config import HotSOSConfig
from hotsos.core.host_helpers.filestat import FileObj
from hotsos.core.host_helpers.systemd import SystemdHelper
from hotsos.core.host_helpers.config import IniConfigBase
from hotsos.core.host_helpers.ssl import SSLCertificate

# Inspired from the pyparsing examples:
# https://github.com/pyparsing/pyparsing/blob/master/examples/eval_arith.py
# https://github.com/pyparsing/pyparsing/blob/master/examples/simpleBool.py
# Enables "packrat" parsing, which adds memoizing to the parsing logic.
pp.ParserElement.enablePackrat()

# ___________________________________________________________________________ #


class Token:
    def __init__(self, tokens):
        self.token = tokens[0]

    @abstractmethod
    def eval(self):
        """Implement this."""

    @staticmethod
    def operator_operands(tokenlist):
        "generator to extract operators and operands in pairs"
        it = iter(tokenlist)
        while 1:
            try:
                yield (next(it), next(it))
            except StopIteration:
                break

# ___________________________________________________________________________ #


class YNotFound():
    """Type for indicating a thing is not found.
    Allows short-circuiting boolean functions to False,
    e.g. systemd('svc-name', 'start_time_secs') > 123 would evaluate to
    False if there's no such service named `svc-name`."""

    def __init__(self, desc):
        self.desc = desc

    def __repr__(self):
        return f"<`{self.desc}` not found>"


class YExprInvalidArgumentException(pp.ParseFatalException):
    def __init__(self, s, loc, msg):
        super().__init__(s, loc, "invalid argument '%s'" % msg)


# ___________________________________________________________________________ #


class LogicalOpBase(Token):
    logical_fn: Callable[
        [Iterable[bool]], bool
    ] = lambda _: False

    def eval(self):
        # Yield odd operands 'True' 'and' 'False' 'and' 'False' 'and' 'True'
        # would yield 'True', 'False', 'False', 'True'
        eval_exprs = (t.eval() for t in self.token[::2])

        return self.logical_fn(eval_exprs)


class YExprLogicalAnd(LogicalOpBase):
    logical_fn = all

    def __repr__(self):
        return " and ".join([str(t.eval()) for t in self.token[::2]])


class YExprLogicalOr(LogicalOpBase):
    logical_fn = any

    def __repr__(self):
        return " or ".join([str(t.eval()) for t in self.token[::2]])


class YExprLogicalNot(Token):
    def __init__(self, tokens):
        self.expr = tokens[0][1]

    def eval(self):
        return not self.expr.eval()

# ___________________________________________________________________________ #


class YExprFnBase(Token):
    """Common base class for all function implementations."""


class YExprFnLen(YExprFnBase):
    """len(expr) function implementation."""
    def __init__(self, tokens):
        self.expr = tokens[1][0]

    def eval(self):
        v = self.expr.eval()
        return len(v) if v else 0


class YExprFnNot(YExprFnBase):
    """not(expr) function implementation."""
    def __init__(self, tokens):
        self.expr = tokens[1][0]

    def eval(self):
        return not self.expr.eval()


class YExprFnFile(YExprFnBase):
    """fstat(fname, prop) function implementation."""

    def __init__(self, tokens):
        self.file_name_v = tokens[1][0]
        self.property_name_v = tokens[1][1]

    def eval(self):
        file_name = self.file_name_v.eval()
        property_name = self.property_name_v.eval()
        # print(f"retrieve prop {property_name} fname {file_name}")
        fobj = FileObj(file_name)
        if hasattr(fobj, property_name):
            return getattr(fobj, property_name)

        raise Exception(f"Unknown file property {property_name}")


class YExprFnSystemd(YExprFnBase):
    """systemd(unit_name, ...property) function implementation."""
    def __init__(self, tokens):
        args = tokens[1]
        if len(args) == 0:
            raise Exception("systemd(...) function expects "
                            "at least one argument.")
        if len(args) > 2:
            raise Exception("systemd(...) function expects "
                            "at most two arguments.")
        self.unit_name_v = args[0]
        self.property_name_v = args[1] if len(args) == 2 else None

    def eval(self):
        service_name = self.unit_name_v.eval()
        service_obj = SystemdHelper([service_name]).services.get(service_name)

        if service_obj:
            # print(f"service obj {service_obj}")
            if not self.property_name_v:
                return True
        else:
            return YNotFound(f"{service_name}")

        property_name = self.property_name_v.eval()

        # print(f"retrieve prop {property_name} service_name {service_name}")
        if hasattr(service_obj, property_name):
            return getattr(service_obj, property_name)

        raise Exception(f"systemd service `{service_name}` object "
                        f"has no such property {property_name}")


class YExprFnReadIni(YExprFnBase):
    def __init__(self, tokens):
        args = tokens[1]
        if len(args) < 2:
            raise Exception("read_ini(...) function expects "
                            "at least two arguments.")
        if len(args) > 4:
            raise Exception("read_ini(...) function expects "
                            "at most four arguments.")
        self.ini_file_path_v = args[0]
        self.key_name_v = args[1]
        self.section_name_v = args[2] if len(args) == 3 else None
        self.default_v = args[3] if len(args) == 4 else None

    def eval(self):
        ini_path = self.ini_file_path_v.eval()
        path = os.path.join(HotSOSConfig.data_root, ini_path)
        ini_file = IniConfigBase(path)
        if not ini_file.exists:
            return YNotFound(f"{path}")

        key = self.key_name_v.eval()
        section = self.section_name_v.eval() if self.section_name_v else None
        value = ini_file.get(key, section, expand_to_list=False)
        # print(f"read_ini eval {path}-{key}-{section} = {value}")
        if self.default_v and value is None:
            return self.default_v.eval()

        return value


class YExprFnReadCert(YExprFnBase):
    def __init__(self, tokens):
        args = tokens[1]
        if len(args) < 1:
            raise Exception("cert(...) function expects "
                            "at least on argument.")
        if len(args) > 2:
            raise Exception("cert(...) function expects "
                            "at most two arguments.")
        self.cert_file_path = args[0]
        self.property_name_v = args[1] if len(args) == 2 else None

    def eval(self):
        cert_path = self.cert_file_path.eval()
        try:
            cert = SSLCertificate(cert_path)
        except Exception:
            return YNotFound(f"{cert_path}")

        if not self.property_name_v:
            return cert is not None

        property_name = self.property_name_v.eval()

        if hasattr(cert, property_name):
            return getattr(cert, property_name)

        raise Exception(f"certificate `{cert_path}` object "
                        f"has no such property {property_name}")


# ___________________________________________________________________________ #


class YExprValueBase:
    def __init__(self, tokens):
        self.raw_value = tokens[0]

    def eval(self):
        raise Exception("must implement this!")


class YExprBoolean(YExprValueBase):
    def eval(self):
        if self.raw_value.lower() == "true":
            return True

        if self.raw_value.lower() == "false":
            return False

        raise Exception(f"Non-boolean string: {self.raw_value}")


class YExprNone(YExprValueBase):
    """None."""
    def eval(self):
        return None


class YExprStringLiteral(YExprValueBase):
    """String literal 'foo'"""
    def eval(self):
        return self.raw_value


class YExprInteger(YExprValueBase):
    def eval(self):
        return int(self.raw_value)


class YExprFloat(YExprValueBase):
    def eval(self):
        return float(self.raw_value)


class YExprRuntimeVariable(YExprValueBase, PythonEntityResolver):
    def eval(self):
        # use PythonEntityResolver to retrieve value associated with
        # the given name.
        v = self.get_property(self.raw_value[1:])
        # print("resolve runtime variable `%s`, value: `%s`",
        #          self.raw_value[1:], v)
        return v


class YExprValue(Token):

    def __repr__(self):
        return self.token.eval()

    def eval(self):
        if isinstance(self.token, YExprValueBase):
            return self.token.eval()

        if isinstance(self.token, YExprFnBase):
            return self.token.eval()

        raise Exception("Unrecognized value token!")

# ___________________________________________________________________________ #


class YExprSignOp(Token):
    "Class to evaluate expressions with a leading + or - sign"

    def __init__(self, tokens):
        self.sign, self.value = tokens[0]

    def eval(self):
        mult = {"+": 1, "-": -1}[self.sign]
        return mult * self.value.eval()


class YExprPowerOp(Token):
    "Class to evaluate power expressions"

    def eval(self):
        if len(self.token) < 3:
            raise Exception("Power operation expects at least 3 tokens.")

        if len(self.token) % 2 == 0:
            raise Exception("Power requires odd amount of tokens.")

        result = self.token[-1].eval()
        for val in self.token[-3::-2]:
            operand = val.eval()
            result = operand ** result
        return result


class YExprMulDivOp(Token):
    "Class to evaluate multiplication and division expressions"

    def eval(self):
        if len(self.token) < 3:
            raise Exception("Mul/div operation expects at least 3 tokens.")

        if len(self.token) % 2 == 0:
            raise Exception("Mul/div requires odd amount of tokens.")

        prod = self.token[0].eval()
        for op, val in self.operator_operands(self.token[1:]):
            if op == "*":
                prod *= val.eval()
            elif op == "/":
                prod /= val.eval()
            else:
                raise Exception(f"Unrecognized operation {op}")

        return prod


class YExprAddSubOp(Token):
    "Class to evaluate addition and subtraction expressions"

    def eval(self):
        if len(self.token) < 3:
            raise Exception("Add/sub operation expects at least 3 tokens.")

        if len(self.token) % 2 == 0:
            raise Exception("Add/sub requires odd amount of tokens.")

        sum_v = self.token[0].eval()
        for op, val in self.operator_operands(self.token[1:]):
            if op == "+":
                sum_v += val.eval()
            elif op == "-":
                sum_v -= val.eval()
            else:
                raise Exception(f"Unrecognized operation {op}")
        return sum_v


class YExprComparisonOp(Token):
    "Class to evaluate comparison expressions"

    ops = {
        "<": lambda lhs, rhs: lhs < rhs,
        "<=": lambda lhs, rhs: lhs <= rhs,
        ">": lambda lhs, rhs: lhs > rhs,
        ">=": lambda lhs, rhs: lhs >= rhs,
        "!=": lambda lhs, rhs: lhs != rhs,
        "==": lambda lhs, rhs: lhs == rhs,
        "LT": lambda lhs, rhs: YExprComparisonOp.ops["<"](lhs, rhs),
        "LE": lambda lhs, rhs: YExprComparisonOp.ops["<="](lhs, rhs),
        "GT": lambda lhs, rhs: YExprComparisonOp.ops[">"](lhs, rhs),
        "GE": lambda lhs, rhs: YExprComparisonOp.ops[">="](lhs, rhs),
        "NE": lambda lhs, rhs: YExprComparisonOp.ops["!="](lhs, rhs),
        "EQ": lambda lhs, rhs: YExprComparisonOp.ops["=="](lhs, rhs),
        "<>": lambda lhs, rhs: YExprComparisonOp.ops["!="](lhs, rhs),
        "IN": lambda lhs, rhs: lhs in rhs
    }

    def eval(self):
        lhs = self.token[0].eval()
        for op, val in self.operator_operands(self.token[1:]):
            op_fn = self.ops[op]
            rhs = val.eval()

            # if either of the operands is not found, return False.
            if isinstance(lhs, YNotFound) or isinstance(rhs, YNotFound):
                return False

            if not op_fn(lhs, rhs):
                break
            lhs = rhs
        else:
            # print("comp result is True")
            return True
        # print("comp result is False")
        return False

# ___________________________________________________________________________ #


def error(exception_type):
    def raise_exception(s, loc, typ):
        raise exception_type(s, loc, typ[0])

    return pp.Word(pp.printables).setParseAction(raise_exception)


def init_parser():
    """Initialize parser for check expressions.

    The grammar currently supports the following constructs:

    Keywords:
        None, True, False
    built-ins:
        integer, float, string literal
    runtime:
        python properties
    functions:
        len(...)
        not(...)
    arithmetic:
        - sign
        - plus/minus
        - exponent
        - mul/div
    boolean:
        - gt/ge
        - lt/le
        - eq/ne
        - in/and/or/not
    """

    # This is a forward declaration because functions can take an expression as
    # an argument..
    expr = pp.Forward()
    # Define `None` as keyword for None
    none_keyword = pp.CaselessKeyword("None")
    none_keyword.setParseAction(YExprNone)
    # Define True & False as their corresponding bool values
    # Example: [True, False, TRUE, FALSE, TrUe, FaLsE]
    boolean_keywords = pp.CaselessKeyword("True") | pp.CaselessKeyword("False")
    boolean_keywords.setParseAction(YExprBoolean)
    # Declare syntax for string literals
    # Example: ['this is a test']
    string_literal = pp.QuotedString("'")
    string_literal.setParseAction(YExprStringLiteral)
    # Declare syntax for integers
    # example: [123, 1, 1234]
    integer = pp.Word(pp.nums)
    integer.setParseAction(YExprInteger)
    # Declare syntax for real numbers (float)
    # example. [1.3, 1.23]
    real = pp.Combine(pp.Word(pp.nums) + "." + pp.Word(pp.nums))
    real.setParseAction(YExprFloat)
    # Declare syntax for Python runtime properties.
    # Properties start with `@` symbol and can contain alphanumeric + '.', '_'`
    # example. [@hotsos.module.class.property_1]
    python_property = pp.Combine("@" + pp.Word(pp.alphanums + "._-:/"))
    python_property.setParseAction(YExprRuntimeVariable)

    # Functions
    lpar, rpar = map(pp.Suppress, "()")
    function_call_tail = pp.Group(
        lpar + pp.Optional(pp.delimited_list(expr)) + rpar)
    # Len
    len_function = pp.CaselessKeyword("len") + function_call_tail
    len_function.setParseAction(YExprFnLen)
    # Not
    not_function = pp.CaselessKeyword("not") + function_call_tail
    not_function.setParseAction(YExprFnNot)
    # fstat(..)
    file_function = pp.CaselessKeyword("file") + function_call_tail
    file_function.setParseAction(YExprFnFile)
    # systemd(...)
    systemd_function = pp.CaselessKeyword("systemd") + function_call_tail
    systemd_function.setParseAction(YExprFnSystemd)
    # read_ini(...)
    read_ini_function = pp.CaselessKeyword("read_ini") + function_call_tail
    read_ini_function.setParseAction(YExprFnReadIni)
    # cert(...)
    read_cert_function = pp.CaselessKeyword("read_cert") + function_call_tail
    read_cert_function.setParseAction(YExprFnReadCert)

    functions = (
        len_function
        | not_function
        | file_function
        | systemd_function
        | read_ini_function
        | read_cert_function
    )

    # The order matters.
    keywords = boolean_keywords | none_keyword
    constants = real | integer | string_literal
    operand = functions | keywords | constants | python_property
    # use parse actions to attach EvalXXX constructors to sub-expressions
    operand.setParseAction(YExprValue)

    # Declare arithmetic operations
    signop = pp.one_of("+ -")
    multop = pp.one_of("* /")
    plusop = pp.one_of("+ -")
    expop = pp.Literal("**")
    arith_expr = pp.infix_notation(
        operand,
        [
            (signop, 1, pp.OpAssoc.RIGHT, YExprSignOp),
            (expop, 2, pp.OpAssoc.LEFT, YExprPowerOp),
            (multop, 2, pp.OpAssoc.LEFT, YExprMulDivOp),
            (plusop, 2, pp.OpAssoc.LEFT, YExprAddSubOp),
        ],
    )

    # Declare comparison/boolean operations
    comparisonop = pp.one_of(" ".join(YExprComparisonOp.ops.keys()),
                             caseless=True)
    comp_expr = pp.infix_notation(
        arith_expr,
        [
            (comparisonop, 2, pp.OpAssoc.LEFT, YExprComparisonOp),
            (pp.CaselessKeyword("not"), 1, pp.OpAssoc.RIGHT, YExprLogicalNot),
            (pp.CaselessKeyword("and"), 2, pp.OpAssoc.LEFT, YExprLogicalAnd),
            (pp.CaselessKeyword("or"), 2, pp.OpAssoc.LEFT, YExprLogicalOr),
        ],
    )

    # Append all of them to "expr". Anything that does not match
    # to the comp_expr is an error.
    expr <<= comp_expr | error(YExprInvalidArgumentException)
    # Ignore comments.
    expr.ignore(pp.python_style_comment)
    expr.ignore(pp.c_style_comment)
    return expr


class YPropertyExpr(YRequirementTypeWithOpsBase):
    _override_keys = ["expression"]
    _overrride_autoregister = True
    parser = init_parser()

    @property
    def input(self):
        return self.content

    @property
    @intercept_exception
    def _result(self):
        ret = self.parser.parse_string(self.input)
        return ret[0].eval()
