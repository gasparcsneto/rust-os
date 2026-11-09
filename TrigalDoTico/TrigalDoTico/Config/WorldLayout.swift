import Foundation

// MARK: - Tipos do mapa

/// Uma área retangular do mapa. Zonas trancadas ficam cobertas de mato até o obstáculo ser limpo.
struct ZoneDef: Sendable {
    let id: Int
    let rect: Rect2
    /// Retângulos de plantação dentro da zona.
    let fields: [Rect2]
}

enum ObstacleKind: String, Sendable {
    case log, deadTree, debris
}

struct ObstacleDef: Sendable {
    let id: String
    let kind: ObstacleKind
    let position: Vec2
    /// "Vida" inicial (o número que flutua em cima).
    let health: Float
    /// Zona liberada quando o obstáculo some.
    let unlocksZone: Int
    /// Zona de onde o jogador alcança o obstáculo.
    let reachableFromZone: Int
}

enum PadKind: String, Sendable, CaseIterable {
    case hireHelper, sickle, coop, bakery, barn, barnUpgrade, wateringCan, boots, oven, training, promo

    /// Nome curto mostrado sobre o pad.
    var title: String {
        switch self {
        case .hireHelper: return "Ajudante"
        case .sickle: return "Foice"
        case .coop: return "Galinheiro"
        case .bakery: return "Padaria"
        case .barn: return "Celeiro"
        case .barnUpgrade: return "Ampliar"
        case .wateringCan: return "Regador"
        case .boots: return "Botas"
        case .oven: return "Forno turbo"
        case .training: return "Treino"
        case .promo: return "Promoção"
        }
    }

    /// Texto que sobe na tela quando a compra termina.
    var doneText: String {
        switch self {
        case .hireHelper: return "NOVO AJUDANTE!"
        case .sickle: return "FOICE MELHOR!"
        case .coop: return "GALINHEIRO!"
        case .bakery: return "PADARIA!"
        case .barn: return "CELEIRO!"
        case .barnUpgrade: return "PILHA MAIOR!"
        case .wateringCan: return "TRIGO MAIS RÁPIDO!"
        case .boots: return "MAIS VELOZ!"
        case .oven: return "PRODUÇÃO MAIS RÁPIDA!"
        case .training: return "AJUDANTES MELHORES!"
        case .promo: return "PREÇOS MAIORES!"
        }
    }
}

enum PadRequirement: Sendable {
    /// A zona precisa estar liberada.
    case zone(Int)
    /// Outro pad precisa ter pelo menos este nível.
    case pad(PadKind, Int)
}

struct PadDef: Sendable {
    let kind: PadKind
    let position: Vec2
    let requires: [PadRequirement]
    /// Um preço por nível; a quantidade de preços é o nível máximo.
    let prices: [Int]
}

// MARK: - Mapa

/// Posições de tudo no mapa. Eixos: x cresce para a direita, z cresce em direção à câmera (sul).
enum WorldLayout {

    static let zones: [ZoneDef] = [
        // Zona inicial: campo, balcão, galinheiro, padaria e celeiro.
        ZoneDef(id: 0,
                rect: Rect2(minX: -7, maxX: 5.2, minZ: -10, maxZ: 4.4),
                fields: [Rect2(minX: -6.4, maxX: -0.4, minZ: -6.0, maxZ: -1.2)]),
        // Oeste: liberada pelo tronco.
        ZoneDef(id: 1,
                rect: Rect2(minX: -15, maxX: -7, minZ: -10, maxZ: 4.4),
                fields: [Rect2(minX: -14.4, maxX: -8.4, minZ: -9.0, maxZ: -1.2)]),
        // Norte: liberada pela árvore seca.
        ZoneDef(id: 2,
                rect: Rect2(minX: -7, maxX: 5.2, minZ: -18, maxZ: -10),
                fields: [Rect2(minX: -6.4, maxX: -0.4, minZ: -17.2, maxZ: -12.4)]),
        // Noroeste: liberada pelos destroços.
        ZoneDef(id: 3,
                rect: Rect2(minX: -15, maxX: -7, minZ: -18, maxZ: -10),
                fields: [Rect2(minX: -14.4, maxX: -8.4, minZ: -17.4, maxZ: -13.2)]),
    ]

    static let obstacles: [ObstacleDef] = [
        ObstacleDef(id: "log", kind: .log, position: Vec2(-7.8, 1.0), health: 200, unlocksZone: 1, reachableFromZone: 0),
        ObstacleDef(id: "deadTree", kind: .deadTree, position: Vec2(-1.0, -10.8), health: 1200, unlocksZone: 2, reachableFromZone: 0),
        ObstacleDef(id: "debris", kind: .debris, position: Vec2(-7.8, -14.8), health: 3000, unlocksZone: 3, reachableFromZone: 2),
    ]

    /// A ordem desta lista é a ordem em que a seta de objetivo aponta para os pads.
    static let pads: [PadDef] = [
        PadDef(kind: .hireHelper, position: Vec2(-5.7, 2.9),
               requires: [.zone(1)], prices: GameConfig.Helpers.prices),
        PadDef(kind: .sickle, position: Vec2(-5.7, 0.4),
               requires: [.pad(.hireHelper, 1)], prices: GameConfig.Sickle.prices),
        PadDef(kind: .coop, position: coopSite,
               requires: [.pad(.sickle, 1)], prices: [GameConfig.Coop.price]),
        PadDef(kind: .bakery, position: bakerySite,
               requires: [.pad(.coop, 1)], prices: [GameConfig.Bakery.price]),
        PadDef(kind: .barn, position: barnSite,
               requires: [.pad(.bakery, 1)], prices: [GameConfig.Barn.price]),
        PadDef(kind: .barnUpgrade, position: Vec2(-1.5, -8.2),
               requires: [.pad(.barn, 1)], prices: GameConfig.Barn.upgradePrices),
        PadDef(kind: .wateringCan, position: Vec2(-11.4, 2.0),
               requires: [.zone(1), .pad(.coop, 1)], prices: GameConfig.Upgrades.wateringPrices),
        PadDef(kind: .boots, position: Vec2(2.6, -12.4),
               requires: [.zone(2)], prices: GameConfig.Upgrades.bootsPrices),
        PadDef(kind: .oven, position: Vec2(2.6, -15.4),
               requires: [.zone(2), .pad(.bakery, 1)], prices: GameConfig.Upgrades.ovenPrices),
        PadDef(kind: .training, position: Vec2(-12.6, -11.4),
               requires: [.zone(3), .pad(.hireHelper, 1)], prices: GameConfig.Upgrades.trainingPrices),
        PadDef(kind: .promo, position: Vec2(-9.8, -11.4),
               requires: [.zone(3)], prices: GameConfig.Upgrades.promoPrices),
    ]

    // MARK: Construções

    static let coopSite = Vec2(3.0, -4.0)
    static let bakerySite = Vec2(3.0, -8.6)
    static let barnSite = Vec2(-4.6, -8.2)
    static let cashMat = Vec2(-2.6, 3.2)

    // MARK: Balcão e filas

    /// Altura do tampo do balcão.
    static let counterTop: Float = 0.9

    /// Ponto de entrega de cada produto sobre o balcão em L.
    static func slotPosition(_ kind: ItemKind) -> Vec2 {
        switch kind {
        case .egg: return Vec2(3.5, 5.0)
        case .pie: return Vec2(6.0, 2.0)
        default: return Vec2(0.5, 5.0)
        }
    }

    /// Lugar do cliente de índice `index` na fila do produto.
    static func queueSpot(_ kind: ItemKind, index: Int) -> Vec2 {
        let step = Float(index) * GameConfig.Customers.queueSpacing
        switch kind {
        case .pie: return Vec2(7.05 + step, 2.0)
        default: return Vec2(slotPosition(kind).x, 6.05 + step)
        }
    }

    /// Direção (yaw) para a qual o cliente olha quando está parado na fila.
    static func queueFacing(_ kind: ItemKind) -> Float {
        kind == .pie ? -.pi / 2 : .pi
    }

    /// Onde os clientes aparecem.
    static func customerSpawn(_ kind: ItemKind) -> Vec2 {
        switch kind {
        case .pie: return Vec2(19, 2.0)
        default: return Vec2(slotPosition(kind).x, 18)
        }
    }

    /// Caminho de saída depois de atendido.
    static func customerExit(_ kind: ItemKind) -> [Vec2] {
        switch kind {
        case .pie: return [Vec2(7.2, 3.5), Vec2(20, 3.5)]
        default:
            let x = slotPosition(kind).x - 1.4
            return [Vec2(x, 6.4), Vec2(x, 19)]
        }
    }

    /// Onde cada ajudante para para descarregar o trigo no balcão.
    static func helperDropSpot(index: Int) -> Vec2 {
        Vec2(0.5 + (Float(index) - 1.5) * 0.55, 3.9)
    }
}
