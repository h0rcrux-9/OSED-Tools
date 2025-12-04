#!/usr/bin/env python3
import argparse
import re

def parse_badchars(badchars_str: str) -> set[int]:
    """
    Recebe uma string tipo: "\\x00\\x09\\x0A\\x0B\\x0C\\x0D\\x20"
    e devolve um set com os valores inteiros correspondentes.
    """
    if not badchars_str:
        return set()

    matches = re.findall(r'\\x([0-9a-fA-F]{2})', badchars_str)
    return {int(m, 16) for m in matches}


def gerar_badchars(badchars_str: str | None) -> str:
    # Se nada for passado, por padrão consideramos só "\x00" identificado
    if badchars_str:
        identified = badchars_str
    else:
        identified = "\\x00"

    bad_set = parse_badchars(badchars_str or "")

    # Começa SEMPRE em 0x01 e vai até 0xFF, excluindo os badchars
    bytes_list = [
        f"\\x{i:02x}" for i in range(1, 256)
        if i not in bad_set
    ]

    linhas = []
    linhas.append(f'# Badchars identified: "{identified}"')
    linhas.append("")
    linhas.append("badchars = (")

    for i in range(0, len(bytes_list), 16):
        chunk = "".join(bytes_list[i:i + 16])
        linhas.append(f'    b"{chunk}"')

    linhas.append(")")
    return "\n".join(linhas)


def main():
    parser = argparse.ArgumentParser(
        description="Gerar badchars em formato Python."
    )
    parser.add_argument(
        "-b", "--bad-chars",
        type=str,
        help=r'Lista de badchars no formato "\x00\x09\x0A..."',
    )
    args = parser.parse_args()

    print(gerar_badchars(args.bad_chars))


if __name__ == "__main__":
    main()
