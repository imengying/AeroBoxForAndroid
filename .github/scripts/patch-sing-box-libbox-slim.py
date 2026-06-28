from pathlib import Path


ROOT = Path.cwd()
DISABLED_BUILD_TAG = "//go:build aerobox_disabled_libbox_feature\n\n"


def read(path: str) -> str:
    return (ROOT / path).read_text()


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly 1 match, found {count}")
    write(path, text.replace(old, new, 1))


def remove_once(path: str, block: str) -> None:
    replace_once(path, block, "")


def disable_go_file(path: str) -> None:
    file_path = ROOT / path
    if not file_path.exists():
        raise SystemExit(f"{path}: file not found")
    disable_existing_go_file(file_path)


def disable_existing_go_file(file_path: Path) -> None:
    text = file_path.read_text()
    if text.startswith("//go:build "):
        lines = text.splitlines(keepends=True)
        first_non_build = 0
        while first_non_build < len(lines):
            line = lines[first_non_build]
            if line.startswith("//go:build ") or line.startswith("// +build ") or line.strip() == "":
                first_non_build += 1
                continue
            break
        text = "".join(lines[first_non_build:])
    file_path.write_text(DISABLED_BUILD_TAG + text)


def patch_service_wrapper() -> None:
    remove_once(
        "experimental/libbox/service.go",
        "\toptions.InterfaceMonitor.RegisterMyInterface(options.Name)\n",
    )


def main() -> None:
    disable_go_file("experimental/libbox/log.go")
    patch_service_wrapper()


if __name__ == "__main__":
    main()
