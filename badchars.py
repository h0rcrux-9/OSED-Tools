import re

# =====================================================================
# CONFIGURAÇÃO
# =====================================================================

# Cola aqui o teu hexdump atual (se estiveres só a gerar o payload,
# podes deixar vazio ou comentar a variável 'dump').
dump = r"""
01 02  GGGGHHHHIIIIQQQQ..
00130386 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14  ..................
00130398 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 5d 06  ........... !"#$].
001303aa 00 00 17 32 91 00 c0 48 76 00 cc 13 00 00 dc 04 13 00  ...2...Hv.........
001303bc 1c f2 b5 00 90 16 13 00 90 36 13 00 00 00 00 00 00 00  .........6........
001303ce 00 00 cb 13 00 00 28 04 13 00 70 17 c2 01 cb 13 00 00  ......(...p.......
001303e0 00 00 00 00 3c 15 13 00 cb 76 94 00 ff ff ff ff 0f aa  ....<....v........
001303f2 9b 00 90 16 13 00 dc 04 13 00 a8 b3 13 00 00 00 00 00  ..................
00130404 de 72 02 67 3c 70 02 67 60 ee ae 00 01 00 00 00 00 00  .r.g<p.g`.........
00130416 00 00 00 00 00 00 5c 14 13 00 00 00 00 00 00 00 00 01  ......\...........
00130428 a8 99 94 00 01 00 00 00 02 00 00 00 01 00 00 00 01 00  ..................
0013043a 00 00 00 00 00 00 04 a5 b5 00 01 00 00 00 0c a5 b5 00  ..................
0013044c 02 00 00 00 14 a5 b5 00 00 00 00 00 00 00 00 00 48 e8  ................H.
0013045e ae 00 01 00 00 00 a8 8f 14 00 50 e8 ae 00 01 00 00 00  ..........P.......
00130470 d8 4e 1b 03 60 4e 1b 03 00 00 00 00 00 00 00 00 18 00  .N..`N............
00130482 00 00 00 00 00 00 1c f2 b5 00 01 00 00 00 14 f2 b5 00  ..................
00130494 02 00 00 00 2c a6 b5 00 03 00 00 00 0c f2 b5 00 04 00  ....,.............
001304a6 00 00 fc f1 b5 00 05 00 00 00 f4 f1 b5 00 06 00 00 00  ..................
001304b8 1c a6 b5 00 07 00 00 00 ec f1 b5 00 08 00 00 00 e0 f1
"""

# Lista de badchars já encontrados (em hex).
# Exemplo: se já descobriste que 0x25 é mau, metes [0x25]
known_badchars = [0x25]   # <-- ajusta isto conforme fores encontrando mais


# =====================================================================
# FUNÇÕES
# =====================================================================

def extract_bytes_from_dump(dump_text: str):
    """Extrai bytes (00–ff) de um hexdump em forma de string."""
    hex_bytes = re.findall(r'\b[0-9a-fA-F]{2}\b', dump_text)
    return [int(b, 16) for b in hex_bytes]


def generate_test_payload(known_badchars):
    """
    Gera bytes de teste de 0x01 a 0xFF.
    Qualquer byte em known_badchars é substituído por 0x90.
    """
    return bytes(0x90 if b in known_badchars else b for b in range(0x01, 0x100))


def find_next_badchar(data_bytes, known_badchars):
    """
    Compara os bytes recebidos com a sequência original 0x01–0xFF,
    ignorando:
      - posições cujo byte original está em known_badchars
      - qualquer byte 0x90 no dump (NOP placeholder)
    Retorna o próximo badchar encontrado ou None se não houver.
    """
    for original in range(0x01, 0x100):
        idx = original - 1  # posição na sequência

        if idx >= len(data_bytes):
            print(f"[!] Dump terminou cedo. Próximo possível badchar: 0x{original:02x}")
            return original

        # Se já sabemos que este byte é mau, ignoramos esta posição
        if original in known_badchars:
            continue

        got = data_bytes[idx]

        # Ignorar qualquer 0x90 na validação
        if got == 0x90:
            continue

        # Se o valor não bate certo, temos um novo badchar
        if got != original:
            print(f"[!] Novo badchar encontrado: esperado 0x{original:02x}, "
                  f"mas recebi 0x{got:02x} na posição {idx}")
            return original

    print("[+] Nenhum novo badchar entre 0x01 e 0xFF (ignorando 0x90 e já conhecidos).")
    return None


def print_payload_as_python_bytes(payload: bytes):
    """
    Imprime o payload no formato:
    badchars  = (
        b"\x01\x02..."
    )
    para copiares diretamente para o teu exploit em Python.
    """
    print("badchars  = (")
    line = '    b"'
    for i, b in enumerate(payload, start=1):
        line += f"\\x{b:02x}"
        if i % 16 == 0:
            line += '"'
            print(line)
            if i != len(payload):
                line = '    b"'
    if len(payload) % 16 != 0:
        line += '"'
        print(line)
    print(")")


# =====================================================================
# MAIN
# =====================================================================

if __name__ == "__main__":
    # 1) Gerar o novo payload de teste
    payload = generate_test_payload(known_badchars)
    print("[*] Payload para testar badchars (com conhecidos substituídos por 0x90):")
    print_payload_as_python_bytes(payload)
    print()

    # 2) Se tiveres dump preenchido, tenta achar o próximo badchar
    if dump.strip():
        data = extract_bytes_from_dump(dump)
        print(f"[*] Bytes extraídos do dump: {len(data)}")
        next_bad = find_next_badchar(data, known_badchars)
        if next_bad is not None:
            print(f"[!] Próximo badchar a adicionar: 0x{next_bad:02x}")
