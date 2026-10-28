import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="WebSentry HTTP security header analyzer")
    parser.add_argument("--cli", metavar="URL", help="Analyze one URL without the desktop interface")
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument("--output", help="Report destination; omit for JSON on stdout")
    parser.add_argument("--self-test", metavar="FILE", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.self_test:
        from gui import self_test
        return self_test(args.self_test)
    if args.cli:
        from engine import ScanError, scan
        from reports import save_report, render_html
        try:
            report = scan(args.cli)
            if args.output:
                save_report(report, args.output, args.format)
                if sys.stdout:
                    print("Report saved:", args.output)
            elif sys.stdout:
                print(render_html(report) if args.format == "html" else json.dumps(report, indent=2, ensure_ascii=False))
            return 0
        except (ScanError, OSError) as exc:
            if sys.stderr:
                print(str(exc), file=sys.stderr)
            return 1
    from gui import run
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
