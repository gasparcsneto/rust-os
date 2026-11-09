import Foundation

/// Tudo que pode ser empilhado, voar em arco ou sair do pool.
enum ItemKind: String, Codable, CaseIterable, Sendable {
    case wheat, egg, pie
    case cash
    case straw, chip

    /// Produtos vendidos no balcão, na ordem do HUD.
    static let products: [ItemKind] = [.wheat, .egg, .pie]

    var emoji: String {
        switch self {
        case .wheat: return "🌾"
        case .egg: return "🥚"
        case .pie: return "🥧"
        case .cash: return "💵"
        default: return ""
        }
    }

    /// Espaçamento (x, z) entre itens deste tipo num monte.
    var pileSpacing: Vec2 {
        switch self {
        case .wheat: return Vec2(0.46, 0.3)
        case .egg: return Vec2(0.34, 0.34)
        case .pie: return Vec2(0.46, 0.46)
        case .cash: return Vec2(0.42, 0.3)
        default: return Vec2(0.3, 0.3)
        }
    }

    /// Altura de cada camada num monte.
    var pileLayerHeight: Float {
        switch self {
        case .wheat: return 0.17
        case .egg: return 0.19
        case .pie: return 0.13
        case .cash: return 0.045
        default: return 0.1
        }
    }
}

/// Retornos sensoriais (som + vibração) disparados pelos sistemas.
enum Feedback {
    case harvest, drop, pickup, coin, pay, chop, build, deny, sell, produce
}

/// Posição de cada item na pilha das costas, no espaço local da âncora da pilha.
enum StackLayout {
    static func position(index: Int, sway: Vec2) -> Vec3 {
        let per = GameConfig.Stack.itemsPerColumn
        let level = index % per
        let column = index / per
        let f = Float(level) / Float(per)
        let bend = f * f * GameConfig.Stack.swayReach
        return Vec3(sway.x * bend,
                    Float(level) * GameConfig.Stack.step,
                    -Float(column) * GameConfig.Stack.columnSpacing + sway.y * bend)
    }
}

/// Escala visual do pé de trigo conforme o progresso da rebrota (0 = recém-cortado, 1 = maduro).
enum CropVisual {
    static func scale(progress: Float) -> Vec3 {
        let p = clamp01(progress)
        let grow = smoothStep((p - 0.3) / 0.7)
        let width = 0.55 + 0.45 * grow
        return Vec3(width, 0.18 + 0.82 * grow, width)
    }
}
