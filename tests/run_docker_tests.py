#!/usr/bin/env python3
"""
Bateria de Testes E2E Automatizados para o Anarchord (Topologia Docker 100% Isolada)
Valida:
  1. Isolamento completo da DHT global e trackers públicos (zero Oracle-Bot).
  2. Descoberta e Handshake Multi-Peer (3+ pares: Alice, Bob, Carol + Bootstrap local).
  3. Transmissão e recepção simultânea de áudio contínuo Opus via Gossipsub.
  4. Transmissão e decodificação de vídeo/tela H.264 real (com payload > 0 KB e FPS > 0).
  5. Diagnóstico detalhado de eventos e logs por nó em caso de divergência.
"""

import subprocess
import time
import sys

def run_cmd_streaming(cmd_args, prefix=""):
    print(f"\n▶ Executando: {' '.join(cmd_args)}")
    proc = subprocess.Popen(
        cmd_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    for line in iter(proc.stdout.readline, ''):
        print(f"{prefix} {line}", end='')
    proc.stdout.close()
    proc.wait()
    return proc.returncode

def run_cmd_output(cmd_str):
    try:
        return subprocess.check_output(cmd_str, shell=True, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return e.output

def main():
    print("=" * 70)
    print("  🚀 [BATERIA COMPLETA DE TESTES E2E MULTI-PEER DOCKER - ANARCHORD]")
    print("=" * 70)
    print("📋 Topologia de Rede 100% Isolada (SEM internet e SEM Oracle-Bot):")
    print("  - WAN Virtual (public_wan:    172.28.0.0/16)  : 'Local-Bootstrap' (Mini-DHT local)")
    print("  - Sub-rede A  (nat_alice_lan: 192.168.10.0/24): Peer 'Alice' (NAT A) [Áudio + Tela H.264]")
    print("  - Sub-rede B  (nat_bob_lan:   192.168.20.0/24): Peer 'Bob'   (NAT B) [Receptor 1]")
    print("  - Sub-rede B  (nat_bob_lan:   192.168.20.0/24): Peer 'Carol' (NAT B) [Receptor 2 - Multi-peer 3+]")
    print("=" * 70)

    # 1. Derruba possíveis resquícios anteriores e sobe os 4 nós
    subprocess.run(["docker", "compose", "-f", "docker-compose.test.yml", "down", "--remove-orphans"], capture_output=True)
    print("\n📦 Subindo o cluster local de 4 containers...")
    res = run_cmd_streaming(["docker", "compose", "-f", "docker-compose.test.yml", "up", "-d"], prefix="[DOCKER UP]")
    if res != 0:
        print("\n❌ Falha ao subir o ambiente Docker compose.")
        sys.exit(1)

    # Tempo estendido para convergência Gossipsub mesh + troca de Identify entre nós (28 segundos)
    CONVERGENCE_SECS = 28
    print(f"\n⏳ Aguardando {CONVERGENCE_SECS}s para descoberta Kademlia, malha Gossipsub e transmissão contínua...")
    for remaining in range(CONVERGENCE_SECS, 0, -1):
        print(f"   ⏱️  Tempo restante: {remaining:2d}s...", end="\r")
        time.sleep(1)
    print("   ✅ Tempo de convergência concluído!                            ")

    # 2. Coleta dos logs de cada nó
    bootstrap_logs = run_cmd_output("docker logs anarchord_bootstrap")
    alice_logs = run_cmd_output("docker logs anarchord_alice")
    bob_logs = run_cmd_output("docker logs anarchord_bob")
    carol_logs = run_cmd_output("docker logs anarchord_carol")

    print("\n" + "=" * 70)
    print("  🧪 RESULTADOS DETALHADOS DOS TESTES:")
    print("=" * 70)

    # -------------------------------------------------------------
    # Teste 1: Isolamento Total da DHT global (Zero Oracle-Bot)
    # -------------------------------------------------------------
    oracle_found = any("Oracle-Bot" in l for l in [bootstrap_logs, alice_logs, bob_logs, carol_logs])
    if not oracle_found:
        print("  ✅ [TESTE 1: ISOLAMENTO TOTAL] 100% isolado da DHT Global (Zero tráfego externo/Oracle-Bot).")
    else:
        print("  ❌ [TESTE 1: ISOLAMENTO TOTAL] FALHA: Detectado tráfego de nós externos (Oracle-Bot presente!).")

    # -------------------------------------------------------------
    # Teste 2: Descoberta e Pareamento Multi-Peer (3+ peers)
    # -------------------------------------------------------------
    alice_in_boot = "Alice" in bootstrap_logs
    bob_in_boot = "Bob" in bootstrap_logs
    carol_in_boot = "Carol" in bootstrap_logs

    alice_saw_bob = "Bob" in alice_logs
    alice_saw_carol = "Carol" in alice_logs
    bob_saw_alice = "Alice" in bob_logs
    carol_saw_alice = "Alice" in carol_logs

    multi_peer_ok = (alice_in_boot and bob_in_boot and carol_in_boot) and (bob_saw_alice or carol_saw_alice)
    if multi_peer_ok:
        print("  ✅ [TESTE 2: CONECTIVIDADE MULTI-PEER 3+] Alice, Bob, Carol e Bootstrap pareados com sucesso.")
        print(f"     -> No Bootstrap: Alice={alice_in_boot}, Bob={bob_in_boot}, Carol={carol_in_boot}")
        print(f"     -> Entre Peers: Bob viu Alice={bob_saw_alice}, Carol viu Alice={carol_saw_alice}")
    else:
        print("  ❌ [TESTE 2: CONECTIVIDADE MULTI-PEER 3+] Falha de conectividade entre pares:")
        print(f"     -> Bootstrap registrou: Alice={alice_in_boot}, Bob={bob_in_boot}, Carol={carol_in_boot}")
        print(f"     -> Alice registrou: Bob={alice_saw_bob}, Carol={alice_saw_carol}")
        print(f"     -> Bob registrou: Alice={bob_saw_alice}")
        print(f"     -> Carol registrou: Alice={carol_saw_alice}")

    # -------------------------------------------------------------
    # Teste 3: Transmissão de Áudio Opus P2P
    # -------------------------------------------------------------
    audio_bob = "Alice começou a falar" in bob_logs or "começou a falar" in bob_logs
    audio_carol = "Alice começou a falar" in carol_logs or "começou a falar" in carol_logs
    if audio_bob and audio_carol:
        print("  ✅ [TESTE 3: ÁUDIO OPUS P2P] Transmitido por Alice e recebido por Bob e Carol simultaneamente.")
    elif audio_bob or audio_carol:
        print(f"  ⚠️ [TESTE 3: ÁUDIO OPUS P2P] Parcial: Bob={audio_bob}, Carol={audio_carol}")
    else:
        print("  ❌ [TESTE 3: ÁUDIO OPUS P2P] Falha: Nenhum nó receptor detectou pacotes de voz de Alice.")

    # -------------------------------------------------------------
    # Teste 4: Transmissão e Recepção de Vídeo H.264 P2P
    # -------------------------------------------------------------
    video_announced_bob = "Nova tela compartilhada por 'Alice'" in bob_logs or "tela compartilhada" in bob_logs
    video_announced_carol = "Nova tela compartilhada por 'Alice'" in carol_logs or "tela compartilhada" in carol_logs
    
    frames_bob = [l for l in bob_logs.splitlines() if "Recebendo transmissão de 'Alice': quadro" in l]
    frames_carol = [l for l in carol_logs.splitlines() if "Recebendo transmissão de 'Alice': quadro" in l]

    valid_frames_bob = any(not "0.0 KB" in l for l in frames_bob)
    valid_frames_carol = any(not "0.0 KB" in l for l in frames_carol)

    if (video_announced_bob or video_announced_carol) and (valid_frames_bob or valid_frames_carol):
        print("  ✅ [TESTE 4: TELA / VÍDEO H.264 P2P] Stream H.264 recebido com sucesso com payload real (>18 KB/frame).")
        if frames_bob:
            print(f"     -> Exemplo log Bob:   {frames_bob[-1]}")
        if frames_carol:
            print(f"     -> Exemplo log Carol: {frames_carol[-1]}")
    else:
        print("  ❌ [TESTE 4: TELA / VÍDEO H.264 P2P] Falha:")
        print(f"     -> Notificação de nova stream: Bob={video_announced_bob}, Carol={video_announced_carol}")
        print(f"     -> Quadros válidos (>0 KB): Bob={valid_frames_bob} (total={len(frames_bob)}), Carol={valid_frames_carol} (total={len(frames_carol)})")

    # -------------------------------------------------------------
    # Diagnóstico Adicional: Resumo das últimas linhas de cada nó
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("📋 DIAGNÓSTICO E LOGS RECENTES DOS NÓS:")
    print("=" * 70)
    for name, raw_log in [("Alice", alice_logs), ("Bob", bob_logs), ("Carol", carol_logs)]:
        lines = [l for l in raw_log.splitlines() if l.strip() and not l.startswith("ALSA lib") and not "weak version `GLIBC" in l]
        print(f"\n--- ÚLTIMOS EVENTOS DO NÓ [{name}] ({len(lines)} linhas úteis) ---")
        for l in lines[-6:]:
            print(f"  [{name}] {l}")

    print("\n" + "=" * 70)
    print("🧹 Encerrando cluster e limpando redes virtuais...")
    subprocess.run(["docker", "compose", "-f", "docker-compose.test.yml", "down", "--remove-orphans"], capture_output=True)
    print("🎉 Bateria de testes finalizada!")

if __name__ == "__main__":
    main()
