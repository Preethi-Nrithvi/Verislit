from app import build_parser


def test_parser_defaults_to_hindi():
    args = build_parser().parse_args(["--message", "hello"])
    assert args.language == "Hindi"


def test_parser_accepts_image_and_model():
    args = build_parser().parse_args(
        ["--image", "message.png", "--model", "custom", "--message", "hello"]
    )
    assert str(args.image) == "message.png"
    assert args.model == "custom"
