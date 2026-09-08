def encryption_normalizer():
    try:
        print("Function normalized!")
    except Exception as e:
        print(f"Woopsie!\n{e}")

def cleartext_digitizer_and_matrixator():
    try:
        print("Function normalized!")
    except Exception as e:
        print(f"Woopsie!\n{e}")

def matrix_validator():
    try:
        print("Function normalized!")
    except Exception as e:
        print(f"Woopsie!\n{e}")

def matrix_encryption():
    try:
        print("Function normalized!")
    except Exception as e:
        print(f"Woopsie!\n{e}")

def matrix_alphabetization_and_dumper():
    try:
        print("Function normalized!")
    except Exception as e:
        print(f"Woopsie!\n{e}")

def cyphertext_writeout():
    try:
        print("Function normalized!")
    except Exception as e:
        print(f"Woopsie!\n{e}")

def main(argv=None):
    ap = argparse.ArgumentParser(prog="anon-report.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd")
    sp.add_parser("keygen"); sp.add_parser("pubkey"); sp.add_parser("selftest")
    p = sp.add_parser("sign"); p.add_argument("file"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True); p.add_argument("--out")
    p = sp.add_parser("verify"); p.add_argument("file"); p.add_argument("sig"); p.add_argument("--roster", required=True)
    p = sp.add_parser("attend"); p.add_argument("--roster", required=True); p.add_argument("--assignment", required=True)
    p.add_argument("--tags", required=True); p.add_argument("--nonce", required=True); p.add_argument("--out", default="attendance.json")
    p.add_argument("--force", action="store_true", help=f"prove even over fewer than {MIN_TAGS} tags")
    p = sp.add_parser("verify-attend"); p.add_argument("proof"); p.add_argument("--roster", required=True); p.add_argument("--tags", required=True)
    p.add_argument("--min-tags", type=int, default=MIN_TAGS); p.add_argument("--expect-pubkey", help="pubkey.txt (or line) this student registered")
    p.add_argument("--expect-nonce", help="the nonce issued to this student")
    p = sp.add_parser("roster"); p.add_argument("dir"); p.add_argument("--course", required=True)
    p.add_argument("--version", required=True); p.add_argument("--coursekey", required=True); p.add_argument("--out", default="roster.json")
    p.add_argument("--dropbox-url", help="http://<onion>.onion/deposit, so students need no --url")
    p = sp.add_parser("tags"); p.add_argument("dir"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True); p.add_argument("--secret"); p.add_argument("--out", default="tags.json")
    p = sp.add_parser("deposit"); p.add_argument("file"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True)
    p.add_argument("--url", help="http://<onion>.onion/deposit"); p.add_argument("--out", help="receipt path")
    p.add_argument("--no-upload", action="store_true", help="just write the receipt")
    p.add_argument("--socks", help="Tor SOCKS5 proxy HOST:PORT (default: try 9150 then 9050)")
    p.add_argument("--direct", action="store_true", help="TESTING ONLY: no Tor (server sees your IP)")
    p = sp.add_parser("upload"); p.add_argument("bundle"); p.add_argument("--url"); p.add_argument("--roster")
    p.add_argument("--socks"); p.add_argument("--direct", action="store_true")
    p = sp.add_parser("verify-bundle"); p.add_argument("bundle"); p.add_argument("--roster", required=True)
    p = sp.add_parser("coursekey"); p.add_argument("--version", required=True)
    p.add_argument("--out-secret"); p.add_argument("--out-public", default="course-key.json")
    p = sp.add_parser("decrypt"); p.add_argument("bundle", help="a bundle file or a directory of them")
    p.add_argument("--roster", required=True); p.add_argument("--secret"); p.add_argument("--out-dir", default="reports")
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help(); return
    if hasattr(a, "assignment") and a.assignment is not None:
        require_assignment(a.assignment)
    {"keygen": cmd_keygen, "pubkey": cmd_pubkey, "selftest": cmd_selftest, "sign": cmd_sign,
     "verify": cmd_verify, "attend": cmd_attend, "verify-attend": cmd_verify_attend,
     "roster": cmd_roster, "tags": cmd_tags, "deposit": cmd_deposit, "upload": cmd_upload,
     "verify-bundle": cmd_verify_bundle, "coursekey": cmd_coursekey, "decrypt": cmd_decrypt}[a.cmd](a)

if __name__ == "__main__":
    main()
