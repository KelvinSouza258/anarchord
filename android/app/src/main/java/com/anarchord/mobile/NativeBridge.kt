package com.anarchord.mobile

import java.nio.ByteBuffer

/**
 * Interface nativa JNI para a biblioteca compartilhada `p2p-ffi` com suporte
 * a troca de dados por memória compartilhada (Zero-Copy DirectByteBuffer).
 */
object NativeBridge {
    init {
        try {
            System.loadLibrary("p2p_ffi")
        } catch (e: UnsatisfiedLinkError) {
            System.err.println("Aviso: libp2p_ffi não carregada em modo desktop/mock: ${e.message}")
        }
    }

    /**
     * Inicia o motor P2P no diretório interno do aplicativo.
     * Retorna o identificador nativo (ponteiro em memória `Long`).
     */
    external fun startSimple(nick: String, dataDir: String, port: Int): Long

    /**
     * Envia mensagem de texto no canal ativo.
     */
    external fun sendMessage(engineHandle: Long, text: String): Int

    /**
     * Troca para o canal de texto especificado (ex: "geral", "anuncios").
     */
    external fun joinChannel(engineHandle: Long, channel: String): Int

    /**
     * Retorna a porta local escutada pelo nó P2P.
     */
    external fun listenPort(engineHandle: Long): Int

    /**
     * Coleta o próximo evento diretamente via memória compartilhada (Zero-Copy).
     * O ByteBuffer aponta diretamente para a memória nativa alocada pelo Rust.
     */
    external fun pollEventDirect(engineHandle: Long): ByteBuffer?

    /**
     * Coleta o próximo evento serializado como String JSON para facilidade de exibição.
     */
    external fun pollEventJson(engineHandle: Long): String?

    /**
     * Envia sinal de encerramento para o nó.
     */
    external fun stop(engineHandle: Long)

    /**
     * Libera a instância nativa da memória heap.
     */
    external fun destroy(engineHandle: Long)
}
