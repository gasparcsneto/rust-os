import RealityKit

/// Texto preso a uma entidade, desenhado pelo SwiftUI na posição projetada na tela.
struct LabelComponent: Component {
    var text: String
    var style: LabelStyle
    /// Deslocamento no espaço local da entidade.
    var offset: Vec3
    /// Linha extra (nome e contador dos pads).
    var detail: String = ""
    /// Ícone de pad desenhado acima do texto.
    var icon: PadKind? = nil
    var visible: Bool = true
    var opacity: Float = 1
}

/// Texto que sobe e some ("+5", "SEM DINHEIRO").
struct FloatingTextComponent: Component {
    var life: Float
    var maxLife: Float
    var rise: Float
}

/// Animação curta de escala (squash & stretch, surgir, sumir).
struct PopComponent: Component {
    enum Style {
        /// Surge do zero passando um pouco do tamanho final.
        case grow
        /// Achata e volta (item pousando).
        case squash
        /// Incha e volta (trigo amadurecendo).
        case bounce
        /// Encolhe até sumir.
        case shrink
    }

    enum Finish {
        case none
        /// Remove a entidade da cena ao terminar.
        case remove
    }

    var style: Style
    var duration: Float
    /// Escala de repouso da entidade.
    var base: Vec3
    var finish: Finish = .none
    var elapsed: Float = 0
}

/// Partícula simples com gravidade (palha, lascas).
struct ParticleComponent: Component {
    var velocity: Vec3
    var spin: Vec3
    var life: Float
}
