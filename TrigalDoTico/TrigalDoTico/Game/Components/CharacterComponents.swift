import RealityKit

/// Marca a entidade controlada pelo joystick.
struct PlayerComponent: Component {}

/// Movimento no plano do chão. Preenchido por quem decide (jogador, IA, clientes)
/// e aplicado pelo `MovementSystem`.
struct MotionComponent: Component {
    /// Velocidade desejada em m/s: (x, z).
    var velocity: Vec2 = .zero
    /// Direção atual do corpo (yaw, em radianos; 0 = olhando para +z).
    var heading: Float = 0
    /// Direção para olhar quando parado (nil = mantém a atual).
    var faceHeading: Float? = nil
    /// Raio de colisão.
    var radius: Float = 0.35
    /// Se verdadeiro, respeita zonas liberadas e construções.
    var constrained: Bool = true
}

/// Referências às partes do boneco, usadas pela animação procedural.
struct CharacterRigComponent: Component {
    var body: Entity
    var legLeft: Entity
    var legRight: Entity
    var armLeft: Entity
    var armRight: Entity
    /// Fase do ciclo de caminhada / respiração.
    var phase: Float = 0
    /// Golpe em andamento (1 = começou agora, 0 = terminou).
    var swing: Float = 0
}

/// Pilha de itens nas costas.
struct CarrierComponent: Component {
    /// Itens confirmados, de baixo para cima.
    var items: [ItemKind] = []
    /// Itens voando em direção à pilha (já reservam espaço).
    var incoming: Int = 0
    var capacity: Int
    /// Entidade-filha onde os itens visuais são pendurados.
    var anchor: Entity
    /// Balanço atual e sua velocidade (mola).
    var sway: Vec2 = .zero
    var swayVelocity: Vec2 = .zero
    /// Mostra "MAX" quando cheia (só o jogador).
    var showsMaxLabel: Bool = false

    var isFull: Bool { items.count + incoming >= capacity }
}

/// Capacidade de ceifar trigo por proximidade.
struct HarvesterComponent: Component {
    var radius: Float
    var interval: Float
    var cooldown: Float = 0
    var isPlayer: Bool
}

/// Estado da IA do ajudante.
struct HelperComponent: Component {
    enum State {
        case seeking
        case toCrop(Int)
        case delivering
    }

    var index: Int
    var state: State = .seeking
    var thinkTimer: Float = 0
}

/// Cliente na fila ou indo embora.
struct CustomerComponent: Component {
    var product: ItemKind
    var wanted: Int
    var received: Int = 0
    var serveTimer: Float = 0.3
    var isLeaving: Bool = false
    var exitPath: [Vec2] = []
    var exitIndex: Int = 0
}

/// Galinha decorativa do galinheiro.
struct ChickenComponent: Component {
    /// Centro do passeio, no espaço local do galinheiro.
    var home: Vec3
    var phase: Float
}
