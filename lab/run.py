#!/usr/bin/env python3
"""Roda os cenários do laboratório.

    python lab/run.py                 # compila a imagem e roda todos
    python lab/run.py chat file       # só cenários cujo nome contém "chat" ou "file"
    python lab/run.py --keep-images   # não apaga as imagens no fim (para repetir com --no-build)
    python lab/run.py --no-build      # usa a imagem anarchord-lab já compilada (de um --keep-images)
    python lab/run.py --keep          # não derruba os contêineres do cenário que falhar
    python lab/run.py --list          # lista os cenários
    python lab/run.py --target-volume # artefatos do cargo num volume do Docker (mais rápido fora do Linux)

Requisitos: Docker (com Compose) e Python 3.9+. Os logs de cada cenário ficam em
lab/results/<cenário>/ (events.log com todos os eventos de todos os nós em ordem de tempo).
"""

import argparse
import asyncio
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from anarlab import SCENARIOS  # noqa: E402
from anarlab.lab import IMAGE, Lab  # noqa: E402
from anarlab.node import StepFailed  # noqa: E402
import scenarios  # noqa: E402,F401  (registra os cenários)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def run_logged(args, log, title):
    print(f"   {title}...", flush=True)
    with open(log, "a", encoding="utf-8") as out:
        out.write("\n$ " + " ".join(args) + "\n")
        out.flush()
        result = subprocess.run(args, stdout=out, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        print(f"❌ Falhou: {title}. Veja {log}")
        sys.exit(2)


def build_image(target_volume):
    """Compila os binários Linux reaproveitando a pasta target do projeto e monta a imagem.

    O cargo roda num contêiner com o projeto montado; os artefatos ficam em target/lab-linux/
    (o target/ normal é do sistema do host e não serve para Linux). Na próxima execução só o
    que mudou é recompilado, e a imagem final só copia os binários.
    """
    project = ROOT.parent
    log = ROOT / "results" / "build.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("", encoding="utf-8")
    print(f"🔨 Compilando (log em {log.relative_to(project)})", flush=True)
    run_logged(["docker", "build", "--target", "toolchain", "-t", "anarchord-toolchain", str(project)], log, "ferramentas de compilação")
    target = ["-v", "anarchord-lab-target:/src/target/lab-linux"] if target_volume else []
    run_logged(
        ["docker", "run", "--rm",
         "-v", f"{project}:/src",
         *target,
         "-v", "anarchord-cargo-registry:/usr/local/cargo/registry",
         "-e", "CARGO_TARGET_DIR=/src/target/lab-linux",
         "-w", "/src",
         "anarchord-toolchain",
         "cargo", "build", "--release", "-p", "p2p-agent", "-p", "p2p-cli"],
        log, "cargo build (só recompila o que mudou)",
    )
    if target_volume:
        # Copia os binários do volume para target/lab-linux, de onde a imagem os pega
        run_logged(
            ["docker", "run", "--rm", "-v", "anarchord-lab-target:/t", "-v", f"{project}:/src", "anarchord-toolchain",
             "sh", "-c", "mkdir -p /src/target/lab-linux/release && cp /t/release/anarchord-agent /t/release/p2p-cli /src/target/lab-linux/release/"],
            log, "copiando binários",
        )
    run_logged(["docker", "build", "--build-arg", "BINS=local", "-t", IMAGE, str(project)], log, f"imagem {IMAGE}")


def cleanup_leftovers():
    """Remove contêineres e redes de execuções anteriores interrompidas (as sub-redes se sobrepõem)"""
    def ids(*args):
        out = subprocess.run(["docker", *args], capture_output=True, text=True).stdout.split()
        return out
    containers = ids("ps", "-aq", "--filter", "name=anarlab_")
    if containers:
        subprocess.run(["docker", "rm", "-f", *containers], capture_output=True)
    networks = ids("network", "ls", "-q", "--filter", "name=anarlab_")
    if networks:
        subprocess.run(["docker", "network", "rm", *networks], capture_output=True)


def remove_images():
    """Apaga as imagens do laboratório (anarchord-lab e anarchord-toolchain). Os artefatos do
    cargo ficam em target/lab-linux, então a próxima compilação só refaz a imagem, não o código"""
    for image in (IMAGE, "anarchord-toolchain"):
        subprocess.run(["docker", "rmi", "-f", image], capture_output=True)
    # Versões anteriores, que ficaram sem nome quando uma compilação nova tomou a tag
    subprocess.run(["docker", "image", "prune", "-f", "--filter", "label=anarchord.lab=1"], capture_output=True)
    print("🧹 Imagens do laboratório removidas (use --keep-images para mantê-las)", flush=True)


def image_exists():
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


async def run_one(name, title, fn, keep, timeout):
    lab = Lab(name, ROOT / "results")
    started = time.time()
    error = None
    try:
        await asyncio.wait_for(fn(lab), timeout)
    except StepFailed as e:
        error = str(e)
    except asyncio.TimeoutError:
        error = f"cenário passou de {timeout} s"
    except Exception:
        error = traceback.format_exc()
    finally:
        await lab.down(keep=keep and error is not None)
    elapsed = time.time() - started
    if error:
        lab_dir = lab.dir.relative_to(ROOT.parent)
        print(f"   ❌ {error}\n      log: {lab_dir}/events.log", flush=True)
    return error is None, elapsed


async def main():
    parser = argparse.ArgumentParser(description="Laboratório de testes distribuídos do Anarchord")
    parser.add_argument("filters", nargs="*", help="roda só cenários cujo nome contém um destes textos")
    parser.add_argument("--no-build", action="store_true", help="não recompila a imagem")
    parser.add_argument("--keep", action="store_true", help="mantém os contêineres de cenários que falharem")
    parser.add_argument("--keep-images", action="store_true", help="não apaga as imagens do laboratório no fim")
    parser.add_argument("--list", action="store_true", help="lista os cenários e sai")
    parser.add_argument("--target-volume", action="store_true",
                        help="artefatos do cargo num volume do Docker em vez de target/lab-linux (mais rápido no Windows/macOS)")
    parser.add_argument("--timeout", type=int, default=420, help="tempo máximo por cenário (s)")
    args = parser.parse_args()

    selected = [s for s in SCENARIOS if not args.filters or any(f in s[0] for f in args.filters)]
    if args.list:
        for name, title, _ in SCENARIOS:
            print(f"{name:28} {title}")
        return 0
    if not selected:
        print("Nenhum cenário corresponde aos filtros.")
        return 1
    if args.no_build and not image_exists():
        print(f"A imagem {IMAGE} não existe: rode sem --no-build (e com --keep-images para reaproveitá-la depois).")
        return 1
    try:
        if not args.no_build:
            build_image(args.target_volume)
        return await run_all(selected, args)
    finally:
        # Com --keep, os contêineres de cenários que falharam ficam para inspeção
        if not args.keep:
            cleanup_leftovers()
        if not args.keep_images:
            remove_images()


async def run_all(selected, args):
    cleanup_leftovers()
    results = []
    for index, (name, title, fn) in enumerate(selected, 1):
        print(f"\n▶ [{index}/{len(selected)}] {title}  ({name})", flush=True)
        ok, elapsed = await run_one(name, title, fn, args.keep, args.timeout)
        print(f"   {'✅' if ok else '❌'} {elapsed:.1f} s", flush=True)
        results.append((name, title, ok, elapsed))

    print("\n" + "=" * 72)
    for name, title, ok, elapsed in results:
        print(f"{'✅' if ok else '❌'}  {elapsed:6.1f} s  {title}")
    passed = sum(1 for r in results if r[2])
    print("=" * 72)
    print(f"{passed}/{len(results)} cenários passaram")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
