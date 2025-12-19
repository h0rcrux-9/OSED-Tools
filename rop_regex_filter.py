#!/usr/bin/env python3

import argparse
import re
from collections import defaultdict, OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional, Set


REGS = ["ESP", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]

RET = r"\bret(?:n|f)?\b(?:\s+(?:0x[0-9A-Fa-f]+|\d+))?"
ANY_OP = r"[^,\n]+"
MEM_ANY = r"[^\]]+"

BLOCK_W = 40
SEP_EQ = "=" * BLOCK_W
SEP_DASH = "-" * BLOCK_W

ROLE_BOTH = "BOTH ARGUMENTS"
ROLE_1ST  = "1st ARGUMENT"
ROLE_2ND  = "2nd ARGUMENT"
ROLE_ONE  = "SINGLE ARGUMENT"

# Always-excluded words (edit this list as you wish)
EXCLUDE_WORDS = ["leave", "call", "adc"]


def mem_reg(reg: str) -> str:
    return rf"{reg}(?:(?:\+|-)\w+)?"


def ordered_unique(seq: Iterable[str]) -> List[str]:
    od = OrderedDict()
    for s in seq:
        od.setdefault(s, None)
    return list(od.keys())


def classify_role(template: str) -> str:
    t = template.replace("{MEMREG}", "{REG}")
    if "{REG}" not in t:
        return ROLE_ONE
    if "," not in t:
        return ROLE_ONE

    left, right = t.split(",", 1)
    in_left = "{REG}" in left
    in_right = "{REG}" in right

    if in_left and in_right:
        return ROLE_BOTH
    if in_left:
        return ROLE_1ST
    if in_right:
        return ROLE_2ND
    return ROLE_ONE



def role_header(role: str, width: int = BLOCK_W) -> str:
    """
    Centered line with EXACTLY 'width' characters.
    Example (40 chars): '---------- 1st ARGUMENT ----------'
    """
    text = f" {role} "
    if len(text) >= width:
        return text[:width]
    dashes = width - len(text)
    left = dashes // 2
    right = dashes - left
    return ("-" * left) + text + ("-" * right)


# ----------------------------
# Badchars support
# ----------------------------

_PACK_ADDR_RE = re.compile(
    r'pack\(\s*["\']<L["\']\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
    re.IGNORECASE
)

def parse_badchars(b: str) -> Set[int]:
    b = b.strip()
    out: Set[int] = set()

    if r"\x" in b:
        for hx in re.findall(r"\\x([0-9A-Fa-f]{2})", b):
            out.add(int(hx, 16))
        return out

    for tok in b.split():
        tok = tok.strip()
        if not tok:
            continue
        if tok.lower().startswith("0x"):
            tok = tok[2:]
        if len(tok) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", tok):
            raise ValueError(f"Invalid badchar token: '{tok}' (expected byte like '55' or '0x55')")
        out.add(int(tok, 16))

    return out


def line_has_badchars_in_pack_addr(line: str, badchars: Set[int]) -> bool:
    m = _PACK_ADDR_RE.search(line)
    if not m:
        return False

    addr = int(m.group(1), 0)
    addr_bytes = addr.to_bytes(4, byteorder="little", signed=False)
    return any(b in badchars for b in addr_bytes)


# ----------------------------
# Always-on word filter (ADDED)
# ----------------------------

def line_has_excluded_words(line: str, words: List[str]) -> bool:
    """
    Returns True if the line contains any excluded word as a whole word (case-insensitive).
    Example: 'leave' matches ' leave ' but not 'cleave'.
    """
    for w in words:
        if re.search(rf"\b{re.escape(w)}\b", line, re.IGNORECASE):
            return True
    return False


def build_patterns() -> Dict[str, List[Tuple[str, str]]]:
    pats: Dict[str, List[Tuple[str, str]]] = {}

    base_arith = [
        rf"\b{{OP}}\b\s+{{REG}}\s*,\s*{{REG}}\b.*{RET}",
        rf"\b{{OP}}\b\s+{{REG}}\s*,\s*{ANY_OP}.*{RET}",
        rf"\b{{OP}}\b\s+{ANY_OP}\s*,\s*{{REG}}\b.*{RET}",
        rf"\b{{OP}}\b\s+dword\s+\[{MEM_ANY}\]\s*,\s*{{REG}}\b.*{RET}",
        rf"\b{{OP}}\b\s+{{REG}}\s*,\s*dword\s+\[{MEM_ANY}\].*{RET}",
        rf"\b{{OP}}\b\s+{{REG}}\s*,\s*0x[0-9A-Fa-f]+\b.*{RET}",
    ]
    for op in ["xor", "add", "sub", "mov"]:
        lst = []
        for p in base_arith:
            templ = p.format(OP=op, REG="{REG}")
            lst.append((templ, classify_role(templ)))
        pats[op.upper()] = lst

    lea1 = rf"\blea\b\s+{ANY_OP}\s*,\s*dword\s+\[{{MEMREG}}\].*{RET}"
    lea2 = rf"\blea\b\s+{{REG}}\s*,\s*dword\s+\[{MEM_ANY}\].*{RET}"
    pats["LEA"] = [(lea1, classify_role(lea1)), (lea2, classify_role(lea2))]

    # OR / AND
    # OR: forces a whitespace before "or" (or start-of-line) => avoids confusion with "xor"
    or_tok = r"(?:(?<=\s)|^)\bor\b"
    and_tok = r"\band\b"

    # OR
    p1 = rf"{or_tok}\s+{ANY_OP}\s*,\s*{{REG}}\b.*{RET}"
    p2 = rf"{or_tok}\s+{{REG}}\s*,\s*{ANY_OP}.*{RET}"
    p3 = rf"{or_tok}\s+{ANY_OP}\s*,\s*dword\s+\[{{MEMREG}}\].*{RET}"
    p4 = rf"{or_tok}\s+{{REG}}\s*,\s*dword\s+\[{MEM_ANY}\].*{RET}"
    pats["OR"] = [(p1, classify_role(p1)), (p2, classify_role(p2)),
                  (p3, classify_role(p3)), (p4, classify_role(p4))]

    # AND (kept as-is, with normal word boundaries)
    q1 = rf"{and_tok}\s+{ANY_OP}\s*,\s*{{REG}}\b.*{RET}"
    q2 = rf"{and_tok}\s+{{REG}}\s*,\s*{ANY_OP}.*{RET}"
    q3 = rf"{and_tok}\s+{ANY_OP}\s*,\s*dword\s+\[{{MEMREG}}\].*{RET}"
    q4 = rf"{and_tok}\s+{{REG}}\s*,\s*dword\s+\[{MEM_ANY}\].*{RET}"
    pats["AND"] = [(q1, classify_role(q1)), (q2, classify_role(q2)),
                   (q3, classify_role(q3)), (q4, classify_role(q4))]

    x1 = rf"\bxchg\b\s+{{REG}}\s*,\s*dword\s+\[{MEM_ANY}\].*{RET}"
    x2 = rf"\bxchg\b\s+{{REG}}\s*,\s*{ANY_OP}.*{RET}"
    x3 = rf"\bxchg\b\s+dword\s+\[{MEM_ANY}\]\s*,\s*{{REG}}\b.*{RET}"
    x4 = rf"\bxchg\b\s+{ANY_OP}\s*,\s*{{REG}}\b.*{RET}"
    pats["XCHG"] = [(x1, classify_role(x1)), (x2, classify_role(x2)),
                    (x3, classify_role(x3)), (x4, classify_role(x4))]

    pu1 = rf"\bpush\b\s+{{REG}}\b.*{RET}"
    pu2 = rf"\bpush\b\s+{{REG}}\b.*\bpop\b.*{RET}"
    pats["PUSH"] = [(pu1, classify_role(pu1)), (pu2, classify_role(pu2))]

    po1 = rf"\bpush\b\s+[^;\n]+.*\bpop\b\s+{{REG}}\b.*{RET}"
    po2 = rf"\bpop\b\s+{{REG}}\b.*{RET}"
    pats["POP"] = [(po1, classify_role(po1)), (po2, classify_role(po2))]

    inc1 = rf"\binc\b\s+{{REG}}\b.*{RET}"
    inc2 = rf"\badd\b\s+{{REG}}\s*,\s*0x[0-9A-Fa-f]+\b.*{RET}"
    pats["INC"] = [(inc1, classify_role(inc1)), (inc2, classify_role(inc2))]

    dec1 = rf"\bdec\b\s+{{REG}}\b.*{RET}"
    dec2 = rf"\bsub\b\s+{{REG}}\s*,\s*0x[0-9A-Fa-f]+\b.*{RET}"
    pats["DEC"] = [(dec1, classify_role(dec1)), (dec2, classify_role(dec2))]

    ne1 = rf"\bneg\b\s+{{REG}}\b.*{RET}"
    ne2 = rf"\bneg\b\s+dword\s+\[{{MEMREG}}\].*{RET}"
    pats["NEG"] = [(ne1, classify_role(ne1)), (ne2, classify_role(ne2))]

    j1 = rf"\bjmp\b\s+{{REG}}\b.*{RET}"
    c1 = rf"\bcall\b\s+{{REG}}\b.*{RET}"
    pats["JMP"] = [(j1, classify_role(j1))]
    pats["CALL"] = [(c1, classify_role(c1))]

    return pats


def run_custom_regex(input_path: Path, user_regex: str, badchars: Optional[Set[int]] = None) -> int:
    rx = re.compile(user_regex, re.IGNORECASE)
    lines = input_path.read_text(encoding="utf-8", errors="replace").splitlines()

    hits = []
    for ln in lines:
        if not rx.search(ln):
            continue

        # Always-on excluded words filter (ADDED)
        if line_has_excluded_words(ln, EXCLUDE_WORDS):
            continue

        if badchars and line_has_badchars_in_pack_addr(ln, badchars):
            continue

        hits.append(ln)

    for ln in hits:
        print(ln)

    return 0 if hits else 1


def run_default(input_path: Path, output_path: Path, badchars: Optional[Set[int]] = None) -> None:
    patterns = build_patterns()
    lines = input_path.read_text(encoding="utf-8", errors="replace").splitlines()

    results: Dict[str, Dict[str, Dict[str, Tuple[List[str], List[str]]]]] = defaultdict(
        lambda: {r: {
            ROLE_BOTH: ([], []),
            ROLE_1ST:  ([], []),
            ROLE_2ND:  ([], []),
            ROLE_ONE:  ([], []),
        } for r in REGS}
    )

    compiled: Dict[Tuple[str, str], List[Tuple[str, List[re.Pattern], List[re.Pattern]]]] = {}

    for mnem, templ_list in patterns.items():
        for reg in REGS:
            memreg = mem_reg(reg)
            items = []
            for templ, role in templ_list:
                rx = templ.replace("{REG}", reg).replace("{MEMREG}", memreg)
                rx_colon = r":\s*" + rx
                items.append((
                    role,
                    [re.compile(rx_colon, re.IGNORECASE)],
                    [re.compile(rx, re.IGNORECASE)],
                ))
            compiled[(mnem, reg)] = items

    for mnem in patterns.keys():
        for reg in REGS:
            seen = set()
            for line in lines:
                if line in seen:
                    continue

                # Always-on excluded words filter (ADDED)
                if line_has_excluded_words(line, EXCLUDE_WORDS):
                    continue

                if badchars and line_has_badchars_in_pack_addr(line, badchars):
                    continue

                for role, colon_res, plain_res in compiled[(mnem, reg)]:
                    if any(r.search(line) for r in colon_res):
                        results[mnem][reg][role][0].append(line)
                        seen.add(line)
                        break
                    if any(r.search(line) for r in plain_res):
                        results[mnem][reg][role][1].append(line)
                        seen.add(line)
                        break

    for mnem in results:
        for reg in REGS:
            for role in [ROLE_BOTH, ROLE_1ST, ROLE_2ND, ROLE_ONE]:
                c, p = results[mnem][reg][role]
                results[mnem][reg][role] = (ordered_unique(c), ordered_unique(p))

    out: List[str] = []
    role_order = [ROLE_BOTH, ROLE_1ST, ROLE_2ND, ROLE_ONE]

    for mnem in patterns.keys():
        for reg in REGS:
            out.append(SEP_EQ)
            out.append(f"GADGET TYPE: {mnem}".center(BLOCK_W))
            out.append(f"REGISTER: {reg}".center(BLOCK_W))
            out.append(SEP_DASH)
            out.append("")

            any_hit = any(
                results[mnem][reg][role][0] or results[mnem][reg][role][1]
                for role in role_order
            )
            if not any_hit:
                out.append("No Results")
                out.append("")
                continue

            for role in role_order:
                colon_hits, plain_hits = results[mnem][reg][role]
                hits = colon_hits + plain_hits
                if not hits:
                    continue

                # Extra blank line before SINGLE ARGUMENT
                if role == ROLE_ONE:
                    out.append("")

                out.append(role_header(role))
                out.append("")
                out.extend(hits)
                out.append("")

            out.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Regex gadgets finder (x86-like), with block output and argument-side classification."
    )
    ap.add_argument("-i", "--input", required=True, help="Input text file.")
    ap.add_argument("-o", "--output", help="Output file (created if missing). Ignored if -r is used.")
    ap.add_argument("-r", "--regex", help='Custom regex (quoted). If set, runs only this regex and prints to stdout.')
    ap.add_argument(
        "-b", "--badchars",
        help='Badchars to filter gadget addresses inside pack("<L", 0x...). '
             'Formats: "\\x00\\x20\\x55" or "00 20 55" (also accepts "0x00 0x20").'
    )
    args = ap.parse_args()

    in_path = Path(args.input)

    badchars: Optional[Set[int]] = None
    if args.badchars:
        badchars = parse_badchars(args.badchars)

    if args.regex:
        raise SystemExit(run_custom_regex(in_path, args.regex, badchars=badchars))

    if not args.output:
        ap.error("Without -r, you must provide -o <output_file>.")

    run_default(in_path, Path(args.output), badchars=badchars)


if __name__ == "__main__":
    main()
