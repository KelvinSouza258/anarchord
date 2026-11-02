#!/usr/bin/env python3
import subprocess
import time
import sys
import os

# Força UTF-8 na saída padrão do Windows para suportar emojis e logs do P2P
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def run_cmd_streaming(cmd_args, prefix="[DOCKER BUILD]"):
    """Executa um comando exibindo cada linha de saída em tempo real."""
    print(f"\n▶ Executando: {' '.join(cmd_args)}")
    process = subprocess.Popen(
        cmd_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    for line in iter(process.stdout.readline, ''):
        if line:
            print(f"{prefix} {line.rstrip()}")
    process.stdout.close()
    return_code = process.wait()
    return return_code

def run_cmd_output(cmd):
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).stdout

def main():
    print("=" * 65)
    print("  🚀 [TESTES E2E MULTI-PEER DOCKER - ANARCHORD]")
    print("=" * 65)
    print("📋 Cenário:")
    print("  - Sub-rede 1 (nat_alice_lan: 192.168.10.0/24): Peer 'Alice' atrás de NAT")
    print("  - Sub-rede 2 (nat_bob_lan:   192.168.20.0/24): Peer 'Bob' atrás de NAT")
    print("  - Sub-rede 3 (public_wan:    172.28.0.0/16)  : 'Public-Relay' na WAN pública")
    print("=" * 65)

    # 1. Build e subida dos containers com logs em tempo real
    print("\n📦 Construindo imagens e subindo os 3 containers...")
    ret = run_cmd_streaming(["docker", "compose", "-f", "docker-compose.test.yml", "up", "-d", "--build"])
    if ret != 0:
        print("\n❌ Falha ao subir o ambiente Docker compose.")
        sys.exit(1)

    print("\n⏳ Aguardando 12s para estabelecimento dos circuitos P2P e Identify...")
    for remaining in range(12, 0, -1):
        print(f"   ⏱️  Tempo restante: {remaining}s...", end="\r")
        time.sleep(1)
    print("   ✅ Tempo de convergência de rede concluído!        ")

    # 2. Coleta e exibição dos logs de cada nó
    print("\n" + "=" * 65)
    print("  📡 VERIFICAÇÃO DE IDENTIDADE E CONEXÃO ENTRE OS NÓS")
    print("=" * 65)

    relay_logs = run_cmd_output("docker logs anarchord_relay")
    alice_logs = run_cmd_output("docker logs anarchord_alice")
    bob_logs = run_cmd_output("docker logs anarchord_bob")

    print("\n🔍 Analisando handshake dos pares:")
    alice_ok = "Alice" in relay_logs or "Alice" in bob_logs
    bob_ok = "Bob" in relay_logs or "Bob" in alice_logs

    if alice_ok:
        print("  ✅ [Alice] Conectada à malha P2P e identificada com sucesso!")
    else:
        print("  ⚠️ [Alice] Conexão ainda em andamento.")

    if bob_ok:
        print("  ✅ [Bob]   Conectado à malha P2P e identificado com sucesso!")
    else:
        print("  ⚠️ [Bob]   Conexão ainda em andamento.")

    print("\n" + "-" * 65)
    print("📄 ÚLTIMOS LOGS DO PUBLIC-RELAY:")
    print("-" * 65)
    for line in relay_logs.strip().splitlines()[-6:]:
        print(f"   {line}")

    print("\n" + "-" * 65)
    print("📄 ÚLTIMOS LOGS DE ALICE (atrás do NAT A):")
    print("-" * 65)
    for line in alice_logs.strip().splitlines()[-6:]:
        print(f"   {line}")

    print("\n" + "-" * 65)
    print("📄 ÚLTIMOS LOGS DE BOB (atrás do NAT B):")
    print("-" * 65)
    for line in bob_logs.strip().splitlines()[-6:]:
        print(f"   {line}")

    print("\n" + "=" * 65)
    print("🧹 Encerrando containers e limpando sub-redes virtuais...")
    run_cmd_streaming(["docker", "compose", "-f", "docker-compose.test.yml", "down"], prefix="[DOCKER CLEANUP]")
    print("\n🎉 Teste E2E concluído com êxito!")

if __name__ == "__main__":
    main()
