import hashlib
from pathlib import Path


ROOT = Path.cwd()
TEMPLATE_ROOT = Path(__file__).resolve().parent.parent / "libbox"
DISABLED_BUILD_TAG = "//go:build aerobox_disabled_libbox_feature\n\n"

UPSTREAM_HASHES = {
    "include/registry.go": "425115ff59461812d94e65f267e28fcd4e4e5875f5e05ae6e284d4c7b5b565fa",
    "include/quic.go": "9bdcd4a12b0c3b5223952eb2a6294e491931bf9fda8bd8a02c574e4228136f8b",
    "experimental/libbox/build_info.go": "6d17d97083202147a1611344f724122e42a94cbda600d555cd57f895ef001a0a",
    "experimental/libbox/command.go": "c4ddafe6af97c5865ca1c00ddd19385b9400613030a464f3bf1a52bdcc1d81ef",
    "experimental/libbox/command_client.go": "3cad8506cbab32c374abb2c5f1b295573de70957369971d1ddca85e656a1aa8b",
    "experimental/libbox/command_types.go": "ef2294ddd3bfef265b61a1f40c06e62f04d589412906223ce8b54101349ee47a",
    "experimental/libbox/deprecated.go": "d3eafe8092bb78276f88e1428ef02876a807d3d9ad5668afe192f776898f2629",
    "experimental/libbox/fdroid.go": "749c57b9a52eaf99a5fcb01a26d1028be10a73859422cadff3b531e18117196b",
    "experimental/libbox/fdroid_mirrors.go": "5a069edecf0766ab35d7dea57ca99dfe3c5307875304179f2767d57a11ca4ed3",
    "experimental/libbox/http.go": "157657c37e10257088b40a7ce4918ebfab1516df5446d396595a619ea655a7c1",
    "experimental/libbox/pprof.go": "8be57f35cedebcff7e325133ce162c2b602162e606362c4f42a1c4c6a12dd3d1",
    "experimental/libbox/profile_import.go": "0ed4698d7dfd428dc3bd65bacec88a56b414892f46ee4e09d76e5e8f2a881254",
    "experimental/libbox/remote_profile.go": "63b30392f33b8cd0d6787105d64a3787446aeefbe24cbb506756131d94d2f895",
    "experimental/libbox/semver.go": "bb023f05f9fbd0ef05802e5006f755880ca2cfb00c8694bca9e585fa1c75c277",
    "experimental/libbox/semver_test.go": "dd0901f2b0ddfc7a4564d067c16f53dc90e11157a810ce2658940fb8de13f9d2",
}

DISABLED_LIBBOX_FILES = (
    "experimental/libbox/build_info.go",
    "experimental/libbox/command.go",
    "experimental/libbox/command_client.go",
    "experimental/libbox/deprecated.go",
    "experimental/libbox/fdroid.go",
    "experimental/libbox/fdroid_mirrors.go",
    "experimental/libbox/http.go",
    "experimental/libbox/pprof.go",
    "experimental/libbox/profile_import.go",
    "experimental/libbox/remote_profile.go",
    "experimental/libbox/semver.go",
    "experimental/libbox/semver_test.go",
)


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


def verify_upstream_file(path: str) -> None:
    file_path = ROOT / path
    if not file_path.exists():
        raise SystemExit(f"{path}: file not found")
    actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
    expected = UPSTREAM_HASHES[path]
    if actual != expected:
        raise SystemExit(
            f"{path}: upstream file changed (expected {expected}, found {actual}); "
            "review the AeroBox slim patch before releasing"
        )


def replace_with_template(path: str, template_name: str) -> None:
    verify_upstream_file(path)
    template_path = TEMPLATE_ROOT / template_name
    if not template_path.exists():
        raise SystemExit(f"{template_path}: template not found")
    write(path, template_path.read_text())


def disable_verified_go_file(path: str) -> None:
    verify_upstream_file(path)
    disable_go_file(path)


def patch_service_wrapper() -> None:
    remove_once(
        "experimental/libbox/service.go",
        "\toptions.InterfaceMonitor.RegisterMyInterface(options.Name)\n",
    )


def main() -> None:
    disable_go_file("experimental/libbox/log.go")
    for path in DISABLED_LIBBOX_FILES:
        disable_verified_go_file(path)
    replace_with_template("experimental/libbox/command_types.go", "command_types.go")
    replace_with_template("include/registry.go", "registry.go")
    replace_with_template("include/quic.go", "quic.go")
    patch_service_wrapper()


if __name__ == "__main__":
    main()
