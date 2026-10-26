"""Install engines v1.0.1, v1.0.2 and v1.0.3 from their tags, each in an
environment of its own, and run `harnas.py` in them.

    python opzetten.py --bron <git-repository met de tags> --werkmap <lege map>
                       [--pakket <kennis.json> --matrix <kennis-regressie.json>]

Per tag, in `<werkmap>/<tag>/`:
1. the commit of the tag in `--bron` must be the pin in `harnas.TAG_PINS`;
2. `git clone --no-checkout` of `--bron`, then a detached checkout of the
   pin, read back (`git rev-parse HEAD`);
3. a new venv; then, with the pip of that venv and in this order, the
   hash-locked `requirements-build.txt` and `requirements-dev.txt` OF THAT
   TAG (`--require-hashes`), then the tag itself
   (`--no-deps --no-build-isolation`) - the three steps the tag's own CI
   runs, so nothing is fetched behind a hash;
4. `python -I harnas.py weigering <tag>` (the fixed expectation: the engine
   refuses a package with `minimaleEngine`), and on v1.0.3 with `--pakket`
   and `--matrix` also `python -I harnas.py regressie <pakket> <matrix>`.

Never touches the 1.1 environment that runs this script, and never the
`--bron` repository beyond reading it. Every step logs a visible
START / OK / WAARSCHUWING / FOUT line; the last line is the end status.
Exit code 0 only when every step and every expectation held.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import venv
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _harness():
    spec = importlib.util.spec_from_file_location("regressie_harnas", HERE / "harnas.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["regressie_harnas"] = module  # dataclasses look their module up there
    spec.loader.exec_module(module)
    return module


def _log(level: str, text: str) -> None:
    print(f"[{level}] {text}", flush=True)


def _run(step: str, command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    _log("START", f"{step}: {' '.join(command)}")
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    for line in (done.stdout + done.stderr).splitlines()[-40:]:
        print(f"    {line}", flush=True)
    if done.returncode != 0:
        _log("FOUT", f"{step}: exitcode {done.returncode}")
        raise SystemExit(1)
    _log("OK", step)
    return done


def _python(environment: Path) -> Path:
    windows = environment / "Scripts" / "python.exe"
    return windows if windows.exists() else environment / "bin" / "python"


def prepare(tag: str, pin: str, source: Path, workdir: Path) -> Path:
    checkout = workdir / tag / "bron"
    environment = workdir / tag / "venv"
    if checkout.exists() or environment.exists():
        _log("FOUT", f"{tag}: {workdir / tag} bestaat al; kies een lege werkmap")
        raise SystemExit(1)
    found = _run(f"{tag}: commit van de tag lezen", ["git", "-C", str(source), "rev-parse", f"{tag}^{{commit}}"])
    if found.stdout.strip() != pin:
        _log("FOUT", f"{tag}: de tag wijst naar {found.stdout.strip()}, de pin is {pin}")
        raise SystemExit(1)
    _run(f"{tag}: kloon", ["git", "clone", "--quiet", "--no-checkout", str(source), str(checkout)])
    _run(f"{tag}: pin uitchecken", ["git", "-C", str(checkout), "checkout", "--quiet", "--detach", pin])
    head = _run(f"{tag}: pin teruglezen", ["git", "-C", str(checkout), "rev-parse", "HEAD"]).stdout.strip()
    if head != pin:
        _log("FOUT", f"{tag}: checkout staat op {head}, niet op {pin}")
        raise SystemExit(1)
    _log("START", f"{tag}: venv in {environment}")
    venv.EnvBuilder(with_pip=True, clear=False).create(environment)
    _log("OK", f"{tag}: venv")
    python = str(_python(environment))
    pip = [python, "-m", "pip", "--disable-pip-version-check", "install", "--quiet"]
    _run(
        f"{tag}: bouwgereedschap (hash-gelockt)",
        [*pip, "--require-hashes", "-r", str(checkout / "requirements-build.txt")],
    )
    _run(
        f"{tag}: afhankelijkheden (hash-gelockt)",
        [*pip, "--require-hashes", "-r", str(checkout / "requirements-dev.txt")],
    )
    _run(f"{tag}: engine van de tag", [*pip, "--no-deps", "--no-build-isolation", str(checkout)])
    return Path(python)


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bron", required=True, type=Path)
    parser.add_argument("--werkmap", required=True, type=Path)
    parser.add_argument("--pakket", type=Path)
    parser.add_argument("--matrix", type=Path)
    options = parser.parse_args(arguments)
    if (options.pakket is None) != (options.matrix is None):
        _log("FOUT", "--pakket en --matrix horen bij elkaar")
        return 2
    harness = _harness()
    workdir = options.werkmap.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    held = True
    try:
        for tag, pin in harness.TAG_PINS.items():
            python = prepare(tag, pin, options.bron.resolve(), workdir)
            refusal = subprocess.run(
                [str(python), "-I", str(HERE / "harnas.py"), "weigering", tag],
                capture_output=True,
                text=True,
                cwd=workdir,
            )
            for line in (refusal.stdout + refusal.stderr).splitlines():
                print(f"    {line}", flush=True)
            if refusal.returncode == 0:
                _log("OK", f"{tag}: weigert een pakket met minimaleEngine")
            else:
                _log("FOUT", f"{tag}: de vaste verwachting (weigering van minimaleEngine) hield niet")
                held = False
            if tag == harness.MATRIX_TAG and options.pakket is not None:
                matrix = subprocess.run(
                    [
                        str(python),
                        "-I",
                        str(HERE / "harnas.py"),
                        "regressie",
                        str(options.pakket.resolve()),
                        str(options.matrix.resolve()),
                    ],
                    capture_output=True,
                    text=True,
                    cwd=workdir,
                )
                for line in (matrix.stdout + matrix.stderr).splitlines():
                    print(f"    {line}", flush=True)
                if matrix.returncode == 0:
                    _log("OK", f"{tag}: regressiematrix klopt")
                else:
                    _log("FOUT", f"{tag}: regressiematrix geweigerd of afwijkend (exitcode {matrix.returncode})")
                    held = False
    except SystemExit as stop:
        _log("FOUT", "afgebroken")
        print("[EINDE] MISLUKT", flush=True)
        return int(stop.code or 1)
    if not held:
        _log("WAARSCHUWING", "een verwachting hield niet")
        print("[EINDE] MISLUKT", flush=True)
        return 1
    print("[EINDE] GESLAAGD", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
