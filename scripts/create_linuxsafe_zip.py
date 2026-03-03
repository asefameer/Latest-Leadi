import argparse
import os
import zipfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Linux-safe zip from a folder")
    parser.add_argument("--src", required=True, help="Source directory")
    parser.add_argument("--out", required=True, help="Output zip path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    src = os.path.abspath(args.src)
    out = os.path.abspath(args.out)

    if not os.path.isdir(src):
        raise FileNotFoundError(f"Source directory not found: {src}")

    exclude_dirs = {".git", "node_modules", "dist", "coverage"}

    parent = os.path.dirname(out)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

    if os.path.exists(out):
        os.remove(out)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for root, dirs, files in os.walk(src):
            dirs[:] = [directory for directory in dirs if directory not in exclude_dirs]
            for file_name in files:
                full_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(full_path, src).replace("\\", "/")
                archive.write(full_path, relative_path)

    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
