package com.anarchord.mobile

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private var engineHandle: Long = 0
    private var isRunning: Boolean = false
    private val mainHandler = Handler(Looper.getMainLooper())

    private lateinit var statusText: TextView
    private lateinit var chatLogText: TextView
    private lateinit var inputMessage: EditText
    private lateinit var sendButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        chatLogText = findViewById(R.id.chatLogText)
        inputMessage = findViewById(R.id.inputMessage)
        sendButton = findViewById(R.id.sendButton)

        sendButton.setOnClickListener {
            val text = inputMessage.text.toString().trim()
            if (text.isNotEmpty() && engineHandle != 0L) {
                thread {
                    NativeBridge.sendMessage(engineHandle, text)
                }
                appendLog("Você: $text")
                inputMessage.text.clear()
            }
        }

        startP2pEngine()
    }

    private fun startP2pEngine() {
        statusText.text = "Iniciando motor P2P nativo..."
        val dataDir = File(filesDir, "anarchord").apply { mkdirs() }.absolutePath
        val nick = "AndroidUser"

        thread {
            try {
                engineHandle = NativeBridge.startSimple(nick, dataDir, 0)
                if (engineHandle != 0L) {
                    val port = NativeBridge.listenPort(engineHandle)
                    mainHandler.post {
                        statusText.text = "🟢 Conectado (#geral) · Porta: $port"
                        Toast.makeText(this@MainActivity, "Nó P2P Ativo!", Toast.LENGTH_SHORT).show()
                    }
                    isRunning = true
                    startEventLoop()
                } else {
                    mainHandler.post {
                        statusText.text = "🔴 Falha ao iniciar nó nativo"
                    }
                }
            } catch (e: Exception) {
                mainHandler.post {
                    statusText.text = "Erro: ${e.message}"
                }
            }
        }
    }

    private fun startEventLoop() {
        thread(name = "p2p-event-loop") {
            while (isRunning && engineHandle != 0L) {
                val eventJson = NativeBridge.pollEventJson(engineHandle)
                if (eventJson != null) {
                    mainHandler.post {
                        handleCoreEvent(eventJson)
                    }
                } else {
                    Thread.sleep(100)
                }
            }
        }
    }

    private fun handleCoreEvent(eventJson: String) {
        // Exibe eventos recebidos do motor P2P
        if (eventJson.contains("ChatMessage")) {
            appendLog("📩 $eventJson")
        } else if (eventJson.contains("PeerIdentified")) {
            appendLog("🤝 Par identificado na rede!")
        } else if (eventJson.contains("Started")) {
            appendLog("🚀 Nó Anarchord no ar!")
        }
    }

    private fun appendLog(msg: String) {
        val current = chatLogText.text.toString()
        val newText = if (current.isEmpty()) msg else "$current\n$msg"
        chatLogText.text = newText
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        if (engineHandle != 0L) {
            val handle = engineHandle
            engineHandle = 0L
            thread {
                NativeBridge.stop(handle)
                NativeBridge.destroy(handle)
            }
        }
    }
}
