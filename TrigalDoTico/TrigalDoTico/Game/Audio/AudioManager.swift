import AVFoundation
import QuartzCore

/// Sons curtos sintetizados em tempo de execução (nenhum arquivo de áudio no projeto).
@MainActor
final class AudioManager {

    enum Sound: CaseIterable {
        case harvest, coin, build, chop, pop, deny, drop
    }

    /// Liga/desliga todos os sons.
    var enabled = true

    private let engine = AVAudioEngine()
    private let sampleRate: Double = 44_100
    private let format: AVAudioFormat?
    private var players: [AVAudioPlayerNode] = []
    private var buffers: [Sound: AVAudioPCMBuffer] = [:]
    private var lastPlayed: [Sound: CFTimeInterval] = [:]
    private var nextPlayer = 0

    init() {
        format = AVAudioFormat(standardFormatWithSampleRate: 44_100, channels: 1)
        guard let format else { return }

        let session = AVAudioSession.sharedInstance()
        try? session.setCategory(.ambient, options: [.mixWithOthers])
        try? session.setActive(true)

        for _ in 0..<6 {
            let player = AVAudioPlayerNode()
            engine.attach(player)
            engine.connect(player, to: engine.mainMixerNode, format: format)
            players.append(player)
        }
        engine.mainMixerNode.outputVolume = 0.8
        buildBuffers()
        startEngine()
    }

    /// Toca um som, ignorando repetições mais próximas que `minGap` segundos.
    func play(_ sound: Sound, minGap: CFTimeInterval = 0.05) {
        guard enabled, let buffer = buffers[sound], !players.isEmpty else { return }
        let now = CACurrentMediaTime()
        if let last = lastPlayed[sound], now - last < minGap { return }
        lastPlayed[sound] = now

        guard engine.isRunning else {
            startEngine()
            return
        }
        let player = players[nextPlayer]
        nextPlayer = (nextPlayer + 1) % players.count
        player.scheduleBuffer(buffer, at: nil, options: .interrupts, completionHandler: nil)
        if !player.isPlaying { player.play() }
    }

    /// Religa o motor de áudio quando o app volta para o primeiro plano.
    func resume() {
        if !engine.isRunning { startEngine() }
    }

    private func startEngine() {
        guard format != nil else { return }
        engine.prepare()
        try? engine.start()
    }

    // MARK: - Síntese

    private func buildBuffers() {
        let twoPi = 2.0 * Double.pi
        var noiseState: UInt32 = 0x1234_5678
        func noise() -> Double {
            noiseState = noiseState &* 1_664_525 &+ 1_013_904_223
            return Double(noiseState >> 8) / Double(1 << 24) * 2 - 1
        }

        // Colheita: "swish" de ruído com um assobio descendente.
        buffers[.harvest] = makeBuffer(duration: 0.11) { t, p in
            let sweep = sin(twoPi * (900 - 500 * p) * t)
            return (noise() * 0.5 + sweep * 0.35) * exp(-t * 34) * 0.3
        }
        // Moeda: duas notas agudas.
        buffers[.coin] = makeBuffer(duration: 0.22) { t, _ in
            let f = t < 0.07 ? 1318.5 : 1760.0
            let local = t < 0.07 ? t : t - 0.07
            return sin(twoPi * f * t) * exp(-local * 16) * 0.26
        }
        // Construção concluída: arpejo maior ascendente.
        buffers[.build] = makeBuffer(duration: 0.62) { t, _ in
            let notes = [523.25, 659.25, 783.99, 1046.5]
            let index = min(notes.count - 1, Int(t / 0.11))
            let local = t - Double(index) * 0.11
            let tone = sin(twoPi * notes[index] * t) + 0.3 * sin(twoPi * notes[index] * 2 * t)
            return tone * exp(-local * 7) * 0.22
        }
        // Madeira: batida grave com estalo.
        buffers[.chop] = makeBuffer(duration: 0.14) { t, _ in
            sin(twoPi * 150 * t) * exp(-t * 38) * 0.55 + noise() * exp(-t * 95) * 0.3
        }
        // "Pop": assobio curto ascendente.
        buffers[.pop] = makeBuffer(duration: 0.09) { t, p in
            sin(twoPi * (420 + 520 * p) * t) * exp(-t * 26) * 0.28
        }
        // Negado: duas notas graves.
        buffers[.deny] = makeBuffer(duration: 0.3) { t, _ in
            let f = t < 0.14 ? 220.0 : 174.6
            let wave = sin(twoPi * f * t) > 0 ? 1.0 : -1.0
            let local = t < 0.14 ? t : t - 0.14
            return wave * exp(-local * 12) * 0.14
        }
        // Entrega: clique suave.
        buffers[.drop] = makeBuffer(duration: 0.06) { t, _ in
            sin(twoPi * 640 * t) * exp(-t * 60) * 0.24
        }
    }

    /// Gera um buffer mono chamando `sample(tempo, progresso 0…1)` para cada amostra.
    private func makeBuffer(duration: Double, _ sample: (Double, Double) -> Double) -> AVAudioPCMBuffer? {
        guard let format else { return nil }
        let frames = AVAudioFrameCount(duration * sampleRate)
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frames),
              let channels = buffer.floatChannelData else { return nil }
        buffer.frameLength = frames
        let data = channels[0]
        for i in 0..<Int(frames) {
            let t = Double(i) / sampleRate
            data[i] = Float(sample(t, t / duration))
        }
        return buffer
    }
}
