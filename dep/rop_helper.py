#!/usr/bin/env python3
import os
import re
import sys
import struct
import argparse
import subprocess

REGEX = re.compile(r'^(0x[0-9A-Fa-f]+)(\:|\s\|)(.*)')
OUTPUT_DIR = "ROP_Gadgets"  # pasta para os outputs


def parse_cli_address(addr_str: str) -> int:
    """
    Interpreta um address vindo da linha de comandos.
    '0x12344321' -> hex
    '12344321'   -> também hex (por conveniência para endereços).
    """
    addr_str = addr_str.strip()
    if addr_str.lower().startswith("0x"):
        return int(addr_str, 16)
    # tratar tudo o resto como hex por default
    return int(addr_str, 16)


def get_pe_image_base(path):
    """Devolve o ImageBase (base address) de um PE (exe/dll) ou None se não for PE."""
    try:
        with open(path, "rb") as f:
            data = f.read(0x1000)
    except OSError:
        return None

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]

    with open(path, "rb") as f:
        f.seek(e_lfanew)
        pe_hdr = f.read(0x200)

    if len(pe_hdr) < 0x40 or pe_hdr[:4] != b"PE\x00\x00":
        return None

    opt = pe_hdr[24:]  # Optional Header
    if len(opt) < 0x40:
        return None

    magic = struct.unpack("<H", opt[:2])[0]

    if magic == 0x10B:          # PE32
        image_base = struct.unpack("<I", opt[0x1C:0x20])[0]
        return image_base
    elif magic == 0x20B:        # PE32+
        image_base = struct.unpack("<Q", opt[0x18:0x20])[0]
        return image_base

    return None


def process_file(path, image_base=None, target_base=None,
                 use_aslr=False, aslr_offset_base=None):
    """
    - Se use_aslr == False:
        gera payload += pack("<L", 0xADDR_AJUSTADO)
    - Se use_aslr == True:
        gera payload += pack("<L", aslr + 0xOFFSET)
    """
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    new_lines = []

    for line in lines:
        stripped = line.rstrip('\n')
        m = REGEX.match(stripped)
        if not m:
            new_lines.append(line)
            continue

        orig_addr_str = m.group(1)          # 0x...
        sep = m.group(2)
        third_group = m.group(3).strip()    # resto da linha

        addr_int = int(orig_addr_str, 16)

        if use_aslr:
            # base usada para calcular o offset
            base_for_offset = aslr_offset_base
            if base_for_offset is None:
                base_for_offset = image_base if image_base is not None else 0

            offset = addr_int - base_for_offset
            # aslr + 0xOFFSET
            expr = f"aslr + 0x{offset:08X}"
            comment = f"{expr}: {third_group}"
            new_line = f'payload += pack("<L", {expr}) # {comment}\n'
        else:
            # Modo endereço absoluto (ajusta se target_base estiver definido)
            if target_base is not None and image_base is not None:
                new_int = (addr_int - image_base) + target_base
                addr_out = f"0x{new_int:08X}"
            else:
                addr_out = f"0x{addr_int:08X}"

            comment = f"{addr_out}: {third_group}"
            new_line = f'payload += pack("<L", {addr_out}) # {comment}\n'

        new_lines.append(new_line)

    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)


def run_ropz_with_fallback(rop_file, ropz_file):
    """
    Corre ropZ.py; se:
      - output contiver 'Loaded 0 gadgets'
      - ou o processo der erro
    então corre ropz_offsec.py em vez disso.
    """
    print(f"[+] A correr ropZ.py -> {ropz_file}")
    try:
        result = subprocess.run(
            [sys.executable, "ropZ.py", rop_file, ropz_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
    except Exception as e:
        print(f"[!] Erro ao correr ropZ.py: {e}")
        result = None

    if result is not None and result.stdout:
        print(result.stdout, end="")

    need_fallback = False

    if result is None:
        need_fallback = True
    else:
        if result.returncode != 0:
            need_fallback = True
        if "Loaded 0 gadgets" in result.stdout:
            need_fallback = True

    if need_fallback:
        print("[!] ropZ.py não encontrou gadgets ou deu erro, a correr ropz_offsec.py...")
        subprocess.run(
            [sys.executable, "ropz_offsec.py", rop_file, ropz_file],
            check=True
        )


def main():
    parser = argparse.ArgumentParser(
        description="Helper para gerar ROP gadgets em formato payload += pack(...)"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Ficheiro de entrada (exe/dll)"
    )
    parser.add_argument(
        "-b", "--base",
        help="Base address alvo / inicial (ex: 0x62501000 ou 62501000 - tratado como hex)"
    )
    parser.add_argument(
        "--aslr", action="store_true",
        help="Em vez de endereços absolutos, gerar 'aslr + offset' nos payloads"
    )

    args = parser.parse_args()

    inputfile = args.input

    # 0) Base address default da imagem
    image_base = get_pe_image_base(inputfile)
    if image_base is not None:
        print(f"[+] ImageBase (default) de '{inputfile}': 0x{image_base:08X}")
    else:
        print(f"[!] Não consegui detetar um PE válido em '{inputfile}' (sem ImageBase).")

    cli_base = None
    if args.base:
        cli_base = parse_cli_address(args.base)
        print(f"[+] Base address fornecido na linha de comandos: 0x{cli_base:08X}")

    # Mensagens de modo
    if args.aslr:
        base_for_offset = cli_base if cli_base is not None else image_base
        if base_for_offset is not None:
            print(f"[+] Modo ASLR ativo: vou gerar 'aslr + offset' "
                  f"(offset calculado a partir de 0x{base_for_offset:08X})")
        else:
            print("[!] Modo ASLR ativo mas não tenho base clara; offsets serão calculados a partir de 0.")
        target_base = None
        aslr_offset_base = base_for_offset
    else:
        target_base = cli_base
        aslr_offset_base = None
        if target_base is not None and image_base is not None:
            delta = target_base - image_base
            print(f"[+] Modo base fixa: endereços serão ajustados para 0x{target_base:08X}")
            print(f"[+] Delta aplicado aos gadgets: {delta:+d} (decimal)")

    # 1) Cria pasta de output se não existir
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    base_name = os.path.basename(inputfile)
    name_no_ext, _ = os.path.splitext(base_name)

    rop_file = os.path.join(OUTPUT_DIR, f"rop_{name_no_ext}.txt")
    ropz_file = os.path.join(OUTPUT_DIR, f"ropz_{name_no_ext}.txt")

    # 2) Executa o rp++
    print(f"[+] A correr rp-win-x86.exe para {inputfile} -> {rop_file}")
    with open(rop_file, 'w', encoding='utf-8') as out:
        subprocess.run(
            ["rp-win-x86.exe", "-f", inputfile, "-r", "10"],
            stdout=out,
            check=True
        )

    # 3) Executa ropZ.py com fallback para ropz_offsec.py
    run_ropz_with_fallback(rop_file, ropz_file)

    # 4) Processa os dois ficheiros com o regex + ajustes de base/ASLR
    print(f"[+] A processar {rop_file}")
    process_file(
        rop_file,
        image_base=image_base,
        target_base=target_base,
        use_aslr=args.aslr,
        aslr_offset_base=aslr_offset_base
    )

    print(f"[+] A processar {ropz_file}")
    process_file(
        ropz_file,
        image_base=image_base,
        target_base=target_base,
        use_aslr=args.aslr,
        aslr_offset_base=aslr_offset_base
    )

    print("[+] Terminado. Os ficheiros estão em ./ROP_Gadgets/")
    print("    from struct import pack  # não te esqueças disto no exploit")


if __name__ == "__main__":
    main()
