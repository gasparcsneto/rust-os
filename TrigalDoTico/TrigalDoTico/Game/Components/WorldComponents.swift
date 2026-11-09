import RealityKit

/// Pé de trigo.
struct CropComponent: Component {
    /// Índice nos vetores paralelos de `GameWorld` (posição e "maduro").
    var index: Int
    var isRipe: Bool = true
    /// Tempo restante até amadurecer.
    var timer: Float = 0
    /// Duração total da rebrota atual.
    var duration: Float = 1
}

/// Obstáculo com "vida" que o jogador corta ficando parado por perto.
struct ObstacleComponent: Component {
    var id: String
    var health: Float
    var unlocksZone: Int
    var hitTimer: Float = 0
    /// Intensidade atual do tremor (1 = acabou de levar uma batida).
    var shake: Float = 0
}

/// Quadrado de compra no chão.
struct PadComponent: Component {
    var kind: PadKind
    var prices: [Int]
    /// Nível já comprado.
    var level: Int
    /// Quanto já foi pago do nível atual.
    var paid: Int
    /// Entidade do preenchimento que cresce com o pagamento.
    var progressFill: Entity
    var payAccumulator: Float = 0
    /// Há quanto tempo o jogador está em cima do pad.
    var dwell: Float = 0
    var noteTimer: Float = 0
    var warnCooldown: Float = 0

    var currentPrice: Int { prices[min(level, prices.count - 1)] }
}
