"""Compile a structured DataPrime subset into Coralogix v3 simpleFilter definitions.

Coralogix v3 standard log alerts (`logsThreshold`, `logsRatioThreshold`,
`logsTimeRelativeThreshold`) accept `simpleFilter` (Lucene + subsystem label filters),
while specs author queries in DataPrime so `montu lint` can enforce identifier contracts.
This compiler parses DataPrime into an AST and translates supported constructs
deterministically: `$d.<field> == '...'` maps to exact `.keyword`, numeric comparisons
map to `.numeric` ranges, non-`message` substring/prefix/suffix methods map to anchored
`.keyword:/.../` regexes, and `$d.message.contains('...')` maps to a tokenized Lucene
phrase query (`"..."`, because OpenSearch `.keyword` truncates multi-KB log bodies). Any
construct outside this subset raises `CompileError`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class CompileError(ValueError):
    """Raised when a DataPrime query uses syntax outside the supported alert subset."""


@dataclass(frozen=True)
class SubsystemFilter:
    value: str
    operation: str


@dataclass(frozen=True)
class SimpleLogFilter:
    lucene_query: str
    subsystems: tuple[SubsystemFilter, ...]

    def to_coralogix(self) -> dict:
        return {
            "simpleFilter": {
                "luceneQuery": self.lucene_query,
                "labelFilters": {
                    "applicationName": [],
                    "subsystemName": [
                        {"value": item.value, "operation": item.operation}
                        for item in self.subsystems
                    ],
                    "severities": [],
                },
            }
        }


@dataclass(frozen=True)
class CompiledRatioQuery:
    numerator: SimpleLogFilter
    denominator: SimpleLogFilter
    group_by: tuple[str, ...]
    numerator_alias: str
    denominator_alias: str


@dataclass(frozen=True)
class Compare:
    field: str
    op: str
    value: str | int | float


@dataclass(frozen=True)
class MethodCall:
    field: str
    method: str
    arg: str


@dataclass(frozen=True)
class Not:
    inner: Expr


@dataclass(frozen=True)
class And:
    items: tuple[Expr, ...]


@dataclass(frozen=True)
class Or:
    items: tuple[Expr, ...]


Expr = Compare | MethodCall | Not | And | Or


@dataclass(frozen=True)
class _GroupByAgg:
    alias: str
    predicate: Expr | None


@dataclass(frozen=True)
class _ParsedGroupBy:
    keys: tuple[str, ...]
    aggregations: tuple[_GroupByAgg, ...]


_TOKEN_RE = re.compile(
    r"""
    (?P<WS>\s+)
    | (?P<OP>\|\||&&|==|!=|>=|<=|[|!().,><])
    | (?P<NUM>-?\d+(?:\.\d+)?)
    | (?P<STR>'(?:\\.|[^'\\])*')
    | (?P<IDENT>[$A-Za-z_][A-Za-z0-9_.$]*)
    """,
    re.VERBOSE,
)

_SUBSYSTEM_OPS = {
    "==": "LOG_FILTER_OPERATION_TYPE_IS_OR_UNSPECIFIED",
    "contains": "LOG_FILTER_OPERATION_TYPE_INCLUDES",
    "startsWith": "LOG_FILTER_OPERATION_TYPE_STARTS_WITH",
    "endsWith": "LOG_FILTER_OPERATION_TYPE_ENDS_WITH",
}

_LUCENE_REGEX_META_RE = re.compile(r'([\\.+*?^$()\[\]{}|/"@#&<>~])')


@dataclass(frozen=True)
class _Tok:
    kind: str
    val: str
    pos: int


def _tokenize(src: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    pos = 0
    while pos < len(src):
        match = _TOKEN_RE.match(src, pos)
        if not match:
            raise CompileError(f"unexpected character at offset {pos}: {src[pos : pos + 20]!r}")
        kind = match.lastgroup or ""
        if kind != "WS":
            tokens.append(_Tok(kind, match.group(), pos))
        pos = match.end()
    return tokens


def _unescape_str(token_val: str) -> str:
    body = token_val[1:-1]
    return body.replace("\\'", "'").replace("\\\\", "\\")


def _split_method_ident(tokens: list[_Tok]) -> list[_Tok]:
    out: list[_Tok] = []
    for idx, tok in enumerate(tokens):
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
        if tok.kind == "IDENT" and "." in tok.val and nxt is not None and nxt.val == "(":
            field_part, method_part = tok.val.rsplit(".", 1)
            out.append(_Tok("IDENT", field_part, tok.pos))
            out.append(_Tok("METHOD", method_part, tok.pos + len(field_part) + 1))
        else:
            out.append(tok)
    return out


class _Parser:
    def __init__(self, tokens: list[_Tok]):
        self.tokens = tokens
        self.idx = 0

    def peek(self) -> _Tok | None:
        return self.tokens[self.idx] if self.idx < len(self.tokens) else None

    def take(self, kind: str | None = None, val: str | None = None) -> _Tok:
        tok = self.peek()
        if tok is None:
            raise CompileError(f"unexpected end of DataPrime query (expected {val or kind})")
        if kind is not None and tok.kind != kind:
            raise CompileError(f"expected {kind} at offset {tok.pos}, got {tok.val!r}")
        if val is not None and tok.val != val:
            raise CompileError(f"expected {val!r} at offset {tok.pos}, got {tok.val!r}")
        self.idx += 1
        return tok

    def parse_expr(self) -> Expr:
        return self._parse_or()

    def _parse_or(self) -> Expr:
        items = [self._parse_and()]
        while (tok := self.peek()) and tok.val == "||":
            self.take("OP", "||")
            items.append(self._parse_and())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def _parse_and(self) -> Expr:
        items = [self._parse_not()]
        while (tok := self.peek()) and tok.val == "&&":
            self.take("OP", "&&")
            items.append(self._parse_not())
        return items[0] if len(items) == 1 else And(tuple(items))

    def _parse_not(self) -> Expr:
        if (tok := self.peek()) and tok.val == "!":
            self.take("OP", "!")
            return Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Expr:
        tok = self.peek()
        if tok is None:
            raise CompileError("unexpected end of filter expression")
        if tok.val == "(":
            self.take("OP", "(")
            inner = self.parse_expr()
            self.take("OP", ")")
            return inner
        ident = self.take("IDENT").val
        nxt = self.peek()
        if nxt and nxt.val == "(":
            raise CompileError(f"unsupported function call {ident}(...) at offset {tok.pos}")
        if nxt and nxt.kind == "METHOD":
            method = self.take("METHOD").val
            if method not in ("contains", "startsWith", "endsWith"):
                raise CompileError(f"unsupported DataPrime method .{method}() on {ident}")
            self.take("OP", "(")
            arg = _unescape_str(self.take("STR").val)
            self.take("OP", ")")
            return MethodCall(ident, method, arg)
        if nxt and nxt.val in ("==", "!=", ">=", "<=", ">", "<"):
            op = self.take("OP").val
            val_tok = self.peek()
            if val_tok is None:
                raise CompileError(f"missing right-hand value after {ident} {op}")
            if val_tok.kind == "STR":
                self.take("STR")
                return Compare(ident, op, _unescape_str(val_tok.val))
            if val_tok.kind == "NUM":
                self.take("NUM")
                num: int | float = float(val_tok.val) if "." in val_tok.val else int(val_tok.val)
                return Compare(ident, op, num)
            raise CompileError(f"unsupported literal {val_tok.val!r} after {ident} {op}")
        raise CompileError(f"expected operator or method call on {ident!r} at offset {tok.pos}")


def _split_stages(tokens: list[_Tok]) -> list[list[_Tok]]:
    stages: list[list[_Tok]] = []
    current: list[_Tok] = []
    depth = 0
    for tok in tokens:
        if tok.val == "(":
            depth += 1
        elif tok.val == ")":
            depth -= 1
        if tok.val == "|" and depth == 0:
            stages.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        stages.append(current)
    return stages


def compile_filter_query(dataprime: str) -> SimpleLogFilter:
    """Compile a single-filter DataPrime query (`source logs | filter ...`) to simpleFilter."""
    stages = _split_stages(_split_method_ident(_tokenize(dataprime)))
    if len(stages) != 2:
        raise CompileError(
            f"expected `source logs | filter <expr>` (2 stages), got {len(stages)} stage(s)"
        )
    _check_source_logs(stages[0])
    expr = _parse_filter_stage(stages[1])
    return _compile_expr_to_simple_filter(expr)


def compile_ratio_query(dataprime: str) -> CompiledRatioQuery:
    """Compile a `source logs | filter ... | groupby ... calculate ...` ratio query."""
    stages = _split_stages(_split_method_ident(_tokenize(dataprime)))
    if len(stages) != 3:
        raise CompileError(
            f"ratio alert expects `source logs | filter <expr> | groupby ... calculate ...` "
            f"(3 stages), got {len(stages)} stage(s)"
        )
    _check_source_logs(stages[0])
    base_expr = _parse_filter_stage(stages[1])
    parsed_gb = _parse_groupby_stage(stages[2])
    if len(parsed_gb.aggregations) != 2:
        raise CompileError(
            f"ratio groupby must calculate 2 columns (numerator and denominator), got {len(parsed_gb.aggregations)}"
        )
    num_agg, den_agg = parsed_gb.aggregations
    if num_agg.predicate is None:
        raise CompileError(f"ratio numerator {num_agg.alias!r} must use count(if(<predicate>))")
    den_expr = base_expr if den_agg.predicate is None else And((base_expr, den_agg.predicate))
    num_expr = _simplify_numerator(base_expr, num_agg.predicate)
    return CompiledRatioQuery(
        numerator=_compile_expr_to_simple_filter(num_expr),
        denominator=_compile_expr_to_simple_filter(den_expr),
        group_by=parsed_gb.keys,
        numerator_alias=num_agg.alias,
        denominator_alias=den_agg.alias,
    )


def _check_source_logs(stage: list[_Tok]) -> None:
    if [tok.val for tok in stage] != ["source", "logs"]:
        raise CompileError(f"first stage must be `source logs`, got {[tok.val for tok in stage]}")


def _parse_filter_stage(stage: list[_Tok]) -> Expr:
    if not stage or stage[0].val != "filter":
        raise CompileError("second stage must start with `filter`")
    parser = _Parser(stage[1:])
    expr = parser.parse_expr()
    trailing = parser.peek()
    if trailing is not None:
        raise CompileError(f"unexpected trailing token {trailing.val!r} in filter")
    return expr


def _parse_groupby_stage(stage: list[_Tok]) -> _ParsedGroupBy:
    parser = _Parser(stage)
    parser.take("IDENT", "groupby")
    keys: list[str] = []
    while True:
        raw_key = parser.take("IDENT").val
        keys.append(_strip_data_prefix(raw_key))
        if (nxt := parser.peek()) and nxt.val == ",":
            parser.take("OP", ",")
        else:
            break
    calc_kw = parser.take("IDENT").val
    if calc_kw not in ("calculate", "aggregate"):
        raise CompileError(f"expected `calculate` or `aggregate` in groupby, got {calc_kw!r}")
    aggs: list[_GroupByAgg] = []
    while True:
        if parser.peek() is None:
            raise CompileError("expected count(...) in groupby calculate")
        fn_name = parser.take("IDENT").val
        if fn_name != "count":
            raise CompileError(f"only count() / count(if(...)) is supported in ratio groupby, got {fn_name!r}")
        parser.take("OP", "(")
        pred: Expr | None = None
        if (inner := parser.peek()) and inner.val != ")":
            parser.take("IDENT", "if")
            parser.take("OP", "(")
            pred = parser.parse_expr()
            parser.take("OP", ")")
        parser.take("OP", ")")
        parser.take("IDENT", "as")
        alias = parser.take("IDENT").val
        aggs.append(_GroupByAgg(alias=alias, predicate=pred))
        if (nxt := parser.peek()) and nxt.val == ",":
            parser.take("OP", ",")
        else:
            break
    trailing = parser.peek()
    if trailing is not None:
        raise CompileError(f"unexpected trailing token {trailing.val!r} in groupby")
    return _ParsedGroupBy(keys=tuple(keys), aggregations=tuple(aggs))


def _flatten_and(expr: Expr) -> list[Expr]:
    if isinstance(expr, And):
        out: list[Expr] = []
        for item in expr.items:
            out.extend(_flatten_and(item))
        return out
    return [expr]


def _simplify_numerator(base_expr: Expr, num_pred: Expr) -> Expr:
    conjuncts = _flatten_and(base_expr)
    if isinstance(num_pred, Compare) and num_pred.op == "==":
        kept: list[Expr] = []
        for item in conjuncts:
            if (
                isinstance(item, Or)
                and all(
                    isinstance(branch, Compare) and branch.field == num_pred.field and branch.op == "=="
                    for branch in item.items
                )
                and any(
                    isinstance(branch, Compare) and branch.value == num_pred.value
                    for branch in item.items
                )
            ):
                continue
            kept.append(item)
        conjuncts = kept
    conjuncts.extend(_flatten_and(num_pred))
    return And(tuple(conjuncts)) if len(conjuncts) > 1 else conjuncts[0]


def _extract_pure_subsystem(expr: Expr) -> list[SubsystemFilter] | None:
    if isinstance(expr, Compare) and expr.field == "$l.subsystemname" and expr.op == "==" and isinstance(expr.value, str):
        return [SubsystemFilter(value=expr.value, operation=_SUBSYSTEM_OPS["=="])]
    if isinstance(expr, MethodCall) and expr.field == "$l.subsystemname" and expr.method in _SUBSYSTEM_OPS:
        return [SubsystemFilter(value=expr.arg, operation=_SUBSYSTEM_OPS[expr.method])]
    if isinstance(expr, Or):
        merged: list[SubsystemFilter] = []
        for branch in expr.items:
            sub = _extract_pure_subsystem(branch)
            if sub is None:
                return None
            merged.extend(sub)
        return merged
    return None


def _is_purely_negative(expr: Expr) -> bool:
    if isinstance(expr, Not):
        return True
    if isinstance(expr, Compare) and expr.op == "!=":
        return True
    if isinstance(expr, Or):
        return all(_is_purely_negative(branch) for branch in expr.items)
    if isinstance(expr, And):
        return all(_is_purely_negative(item) for item in expr.items)
    return False


def _compile_expr_to_simple_filter(expr: Expr) -> SimpleLogFilter:
    conjuncts = _flatten_and(expr)
    # Exact string equality (`f == 'X'`) subsumes `!f.contains('Y')` whenever `'Y' not in 'X'`.
    exact_strings: dict[str, set[str]] = {}
    for conj in conjuncts:
        if isinstance(conj, Compare) and conj.op == "==" and isinstance(conj.value, str):
            exact_strings.setdefault(conj.field, set()).add(conj.value)

    subsystems: list[SubsystemFilter] = []
    remaining: list[Expr] = []
    for item in conjuncts:
        if (
            isinstance(item, Not)
            and isinstance(item.inner, MethodCall)
            and item.inner.method == "contains"
            and item.inner.field in exact_strings
            and all(item.inner.arg not in pinned for pinned in exact_strings[item.inner.field])
        ):
            continue
        sub = _extract_pure_subsystem(item)
        if sub is not None and not subsystems:
            subsystems.extend(sub)
            continue
        remaining.append(item)

    if remaining and all(_is_purely_negative(item) for item in remaining):
        raise CompileError(
            "filter cannot consist solely of negative clauses in Coralogix Lucene (add a positive `$d.` predicate)"
        )
    lucene_parts = _render_conjuncts(remaining)
    sorted_subs = tuple(sorted(subsystems, key=lambda item: (item.value, item.operation)))
    return SimpleLogFilter(
        lucene_query=" AND ".join(lucene_parts),
        subsystems=sorted_subs,
    )


@dataclass
class _NumericBounds:
    lo_inclusive: bool = True
    lo_val: int | float = 0
    hi_inclusive: bool = True
    hi_val: int | float = 0
    has_lo: bool = False
    has_hi: bool = False


def _render_conjuncts(conjuncts: list[Expr]) -> list[str]:
    bounds: dict[str, _NumericBounds] = {}
    passthrough: list[Expr] = []
    field_order: list[str] = []

    for item in conjuncts:
        if (
            isinstance(item, Compare)
            and item.field.startswith("$d.")
            and isinstance(item.value, (int, float))
            and item.op in (">=", ">", "<=", "<")
        ):
            fname = _strip_data_prefix(item.field)
            if fname not in bounds:
                bounds[fname] = _NumericBounds()
                field_order.append(fname)
            entry = bounds[fname]
            if item.op in (">=", ">"):
                if entry.has_lo:
                    raise CompileError(f"duplicate lower numeric bound on {item.field}")
                entry.has_lo = True
                entry.lo_inclusive = item.op == ">="
                entry.lo_val = item.value
            else:
                if entry.has_hi:
                    raise CompileError(f"duplicate upper numeric bound on {item.field}")
                entry.has_hi = True
                entry.hi_inclusive = item.op == "<="
                entry.hi_val = item.value
        else:
            passthrough.append(item)

    rendered = [_render_lucene(item, allow_not=True) for item in passthrough]
    for fname in field_order:
        entry = bounds[fname]
        if entry.has_lo and entry.has_hi and (
            entry.lo_val > entry.hi_val
            or (entry.lo_val == entry.hi_val and not (entry.lo_inclusive and entry.hi_inclusive))
        ):
            raise CompileError(
                f"empty/inverted numeric range on $d.{fname}: {entry.lo_val} .. {entry.hi_val}"
            )
        lo_str = str(entry.lo_val) if entry.has_lo else "*"
        hi_str = str(entry.hi_val) if entry.has_hi else "*"
        left = "[" if (not entry.has_lo or entry.lo_inclusive) else "{"
        right = "]" if (not entry.has_hi or entry.hi_inclusive) else "}"
        rendered.append(f"{fname}.numeric:{left}{lo_str} TO {hi_str}{right}")
    return rendered


def _strip_data_prefix(field_name: str) -> str:
    if not field_name.startswith("$d."):
        raise CompileError(
            f"unsupported field {field_name!r} (use $d.<field> for log data or $l.subsystemname for subsystem)"
        )
    fname = field_name[3:]
    if not fname or fname.startswith(".") or fname.endswith(".") or ".." in fname:
        raise CompileError(f"malformed DataPrime field path {field_name!r}")
    return fname


def _escape_phrase(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"')


def _escape_regex(val: str) -> str:
    return _LUCENE_REGEX_META_RE.sub(r"\\\1", val)


def _negate_expr(expr: Expr) -> Expr | None:
    if isinstance(expr, Not):
        return expr.inner
    if isinstance(expr, Compare) and expr.op == "!=":
        return Compare(expr.field, "==", expr.value)
    return None


def _render_lucene(expr: Expr, *, allow_not: bool = False) -> str:
    if isinstance(expr, And):
        items = _flatten_and(expr)
        if not allow_not and all(_is_purely_negative(item) for item in items):
            raise CompileError("purely negative `&&` group inside `||` is not supported in Coralogix Lucene")
        body = " AND ".join(_render_conjuncts(items))
        return body if allow_not else f"({body})"

    if isinstance(expr, Or):
        return _render_or(expr, allow_not=allow_not)

    if isinstance(expr, Not):
        if not allow_not:
            raise CompileError("negation inside `||` is not supported in Coralogix Lucene")
        return f"NOT {_render_lucene(expr.inner, allow_not=False)}"

    if isinstance(expr, Compare):
        return _render_compare(expr, allow_not=allow_not)

    if isinstance(expr, MethodCall):
        return _render_method_call(expr)

    raise CompileError(f"unsupported AST node: {expr!r}")


def _render_or(expr: Or, *, allow_not: bool) -> str:
    negated_inners = [_negate_expr(branch) for branch in expr.items]
    if all(inner is not None for inner in negated_inners):
        if not allow_not:
            raise CompileError("nested negated `||` inside another `||` is not supported in Lucene")
        demorgan = And(tuple(inner for inner in negated_inners if inner is not None))
        return f"NOT ({_render_lucene(demorgan, allow_not=True)})"
    if any(inner is not None for inner in negated_inners):
        raise CompileError(
            "mixing `!=` / `!` with positive branches inside `||` is not supported in Coralogix Lucene"
        )
    if all(
        isinstance(branch, Compare) and branch.op == "==" and isinstance(branch.value, str)
        for branch in expr.items
    ):
        fields = {branch.field for branch in expr.items if isinstance(branch, Compare)}
        if len(fields) == 1:
            only_field = next(iter(fields))
            if only_field.startswith("$d."):
                fname = _strip_data_prefix(only_field)
                if fname == "message":
                    raise CompileError(
                        "$d.message does not support `==` (message.keyword is truncated on long logs; use $d.message.contains)"
                    )
                vals = " OR ".join(
                    f'"{_escape_phrase(str(branch.value))}"'
                    for branch in expr.items
                    if isinstance(branch, Compare)
                )
                return f"{fname}.keyword:({vals})"
    body = " OR ".join(_render_lucene(branch, allow_not=False) for branch in expr.items)
    return f"({body})"


def _render_compare(expr: Compare, *, allow_not: bool) -> str:
    if expr.op == "!=" and not allow_not:
        raise CompileError("`!=` inside `||` is not supported in Coralogix Lucene")
    if expr.field == "$l.subsystemname":
        if not isinstance(expr.value, str) or expr.op not in ("==", "!="):
            raise CompileError(f"unsupported comparison on $l.subsystemname: {expr.op}")
        term = f'coralogix.metadata.subsystemName:"{_escape_phrase(expr.value)}"'
        return f"NOT {term}" if expr.op == "!=" else term

    fname = _strip_data_prefix(expr.field)
    if fname == "message":
        raise CompileError(
            f"$d.message does not support `{expr.op}` (message.keyword is truncated on long logs; use $d.message.contains)"
        )
    if isinstance(expr.value, str):
        term = f'{fname}.keyword:"{_escape_phrase(expr.value)}"'
        if expr.op == "==":
            return term
        if expr.op == "!=":
            return f"NOT {term}"
        raise CompileError(f"string field {expr.field} does not support operator {expr.op!r}")

    if expr.op == "==":
        return f"{fname}.numeric:{expr.value}"
    if expr.op == "!=":
        return f"NOT {fname}.numeric:{expr.value}"
    return _render_conjuncts([expr])[0]


def _render_method_call(expr: MethodCall) -> str:
    esc = _escape_regex(expr.arg)
    if expr.field == "$l.subsystemname":
        if expr.method == "contains":
            return f"coralogix.metadata.subsystemName:/.*{esc}.*/"
        if expr.method == "startsWith":
            return f"coralogix.metadata.subsystemName:/{esc}.*/"
        return f"coralogix.metadata.subsystemName:/.*{esc}/"
    fname = _strip_data_prefix(expr.field)
    if fname == "message":
        if expr.method == "contains":
            return f'"{_escape_phrase(expr.arg)}"'
        raise CompileError(
            f"$d.message.{expr.method}() is unsupported (message.keyword is truncated on long logs; use $d.message.contains)"
        )
    if expr.method == "contains":
        return f"{fname}.keyword:/.*{esc}.*/"
    if expr.method == "startsWith":
        return f"{fname}.keyword:/{esc}.*/"
    return f"{fname}.keyword:/.*{esc}/"
