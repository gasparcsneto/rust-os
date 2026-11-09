import RealityKit

/// Identifica o tipo de uma entidade do pool.
struct ItemComponent: Component {
    var kind: ItemKind
}

/// O que acontece quando um item em voo chega ao destino.
enum FlightArrival {
    /// Só efeito visual.
    case none
    /// Entra na pilha do `receiver`.
    case stack(ItemKind)
    /// Soma esta quantidade ao monte do `receiver`.
    case pile(Int)
    /// Soma esta quantia à carteira do jogador.
    case wallet(Int)
}

/// Item voando em arco.
struct FlightComponent: Component {
    var start: Vec3
    /// Entidade perseguida (pode se mover durante o voo). Se nil, `targetOffset` é uma posição do mundo.
    var target: Entity?
    /// Deslocamento no espaço local do alvo.
    var targetOffset: Vec3
    /// Entidade cujo componente recebe o item na chegada.
    var receiver: Entity?
    var arrival: FlightArrival
    var duration: Float
    var arc: Float
    var elapsed: Float = 0
}

/// Monte de itens iguais (estoque do balcão, bandejas, tapete do dinheiro).
/// Os filhos da entidade são só os itens visuais, mantidos pelo `PileSystem`.
struct PileComponent: Component {
    var kind: ItemKind
    var count: Int = 0
    /// Quantidade em voo, a caminho do monte.
    var incoming: Int = 0
    var capacity: Int
    var columns: Int = 2
    var rows: Int = 2
    var maxVisible: Int = 16
    /// Quantas unidades cada item visual representa (dinheiro usa mais de 1).
    var unitsPerVisual: Int = 1

    /// Itens visuais necessários para representar `amount` unidades.
    func visuals(for amount: Int) -> Int {
        min(maxVisible, (max(0, amount) + unitsPerVisual - 1) / unitsPerVisual)
    }

    /// Posição local do item visual de índice `index`.
    func slot(_ index: Int) -> Vec3 {
        let perLayer = columns * rows
        let layer = index / perLayer
        let rest = index % perLayer
        let column = rest % columns
        let row = rest / columns
        let spacing = kind.pileSpacing
        return Vec3((Float(column) - Float(columns - 1) / 2) * spacing.x,
                    Float(layer) * kind.pileLayerHeight,
                    (Float(row) - Float(rows - 1) / 2) * spacing.y)
    }

    /// Onde o próximo item que chegar vai pousar.
    var landingSlot: Vec3 {
        slot(min(maxVisible - 1, visuals(for: count + incoming)))
    }

    /// De onde sai o próximo item retirado.
    var takeoffSlot: Vec3 {
        slot(max(0, visuals(for: count) - 1))
    }
}

/// Troca automática de itens por proximidade entre um monte e quem carrega.
struct StationComponent: Component {
    enum Mode {
        /// Pilha das costas → monte.
        case deposit
        /// Monte → pilha das costas.
        case pickup
        /// Monte de dinheiro → carteira.
        case cashCollect
    }

    var mode: Mode
    var radius: Float
    var interval: Float
    var timer: Float = 0
    /// Se verdadeiro, ajudantes não usam esta estação.
    var playerOnly: Bool
}

/// Transforma itens dos montes de entrada em itens do monte de saída.
struct ProducerComponent: Component {
    var inputs: [Entity]
    var costs: [Int]
    var output: Entity
    var interval: Float
    var timer: Float = 0
    /// Modelo que dá um "pulinho" a cada produção.
    var model: Entity
}
