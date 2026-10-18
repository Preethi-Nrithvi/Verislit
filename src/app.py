"""Command-line entry point for Verislit."""

import argparse
from pathlib import Path
import sys

from explain import explain


LANGUAGES = ("Hindi", "Tamil", "Bengali", "Marathi", "Telugu", "Kannada")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Explain a confusing message in a selected Indian language."
    )
    parser.add_argument("--language", choices=LANGUAGES, default="Hindi")
    parser.add_argument(
        "--message",
        help="message to explain; if omitted, read it from standard input",
    )
    parser.add_argument("--image", type=Path, help="path to a screenshot")
    parser.add_argument("--model", help="Ollama model name")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    message = args.message if args.message is not None else sys.stdin.read()
    if not message.strip() and args.image is None:
        raise SystemExit("Provide a message with --message/stdin or an --image path.")

    image_bytes = None
    if args.image is not None:
        try:
            image_bytes = args.image.read_bytes()
        except OSError as error:
            raise SystemExit(f"Could not read image {args.image}: {error}") from error

    try:
        options = {"language": args.language, "image_bytes": image_bytes}
        if args.model:
            options["model"] = args.model
        print(explain(message, **options))
    except Exception as error:
        raise SystemExit(
            f"Could not reach the model. Is Ollama running? ({error})"
        ) from error


if __name__ == "__main__":
    main()