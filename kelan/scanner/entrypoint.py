"""kelan — top-level CLI dispatcher.

Installed as the `kelan` console_scripts entry point by pyproject.toml.
Delegates subcommands to their respective modules.

Usage:
    kelan scan [options]    # AI-native SAST scanner
    kelan help
"""
import sys


def main() -> int:
    argv = sys.argv[1:]
    if not argv or argv[0] in ("help", "--help", "-h"):
        _print_help()
        return 0

    subcmd = argv[0]
    rest = argv[1:]

    if subcmd == "scan":
        from kelan.scanner.cli import main as scan_main
        return scan_main(rest) or 0

    if subcmd == "dast":
        from kelan.dast.cli import main as dast_main
        return dast_main(rest) or 0

    print(f"❌  Unknown subcommand: {subcmd}", file=sys.stderr)
    _print_help()
    return 1


def _print_help() -> None:
    print("""
  kelan — AI-native security toolkit

  Subcommands:
    scan    Static AST-based vulnerability analysis (SAST)
    dast    Dynamic agentic endpoint analysis (DAST)
    help    Show this message

  Examples:
    kelan scan                              # interactive
    kelan scan --target kelan/api --limit 5
    kelan dast --target http://localhost:8080
    kelan dast --target http://localhost:8080 --model qwen2.5-coder:latest
""")


if __name__ == "__main__":
    sys.exit(main())
