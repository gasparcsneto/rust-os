import CoreGraphics
import Observation

/// Aparência de um texto flutuante desenhado sobre a cena.
enum LabelStyle: Sendable {
    /// Balão de pedido do cliente.
    case bubble
    /// Ícone + preço de um pad.
    case pad
    /// Vida de um obstáculo.
    case health
    /// "MAX" sobre a pilha.
    case max
    /// Ganhos e conquistas ("+12").
    case gain
    /// Avisos em vermelho ("SEM DINHEIRO").
    case warning
    /// Etiqueta redonda de produto.
    case tag
}

/// Um texto já projetado em coordenadas de tela.
struct ScreenLabel: Identifiable, Equatable {
    let id: UInt64
    var text: String
    var detail: String
    var style: LabelStyle
    var icon: PadKind?
    var x: CGFloat
    var y: CGFloat
    var opacity: Double
}

/// Estado observado pelo HUD. Os sistemas ECS escrevem aqui; o SwiftUI só lê.
@MainActor
@Observable
final class GameState {
    var money = 0
    var wheat = 0
    var eggs = 0
    var pies = 0
    /// Textos flutuantes do quadro atual.
    var labels: [ScreenLabel] = []
    var soundOn = true
    /// Mostra a mão "Arraste para mover".
    var showMoveHint = true
    var showMenu = true
    /// Existe progresso salvo (troca "Jogar" por "Continuar").
    var hasProgress = false
}
