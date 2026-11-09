import Foundation
import CoreGraphics
import RealityKit

/// Projeta os `LabelComponent` na tela e entrega a lista ao `GameState`,
/// onde o SwiftUI desenha balões, preços, vidas e textos de feedback.
struct LabelSystem: System {
    private let labelQuery = EntityQuery(where: .has(LabelComponent.self))
    private let floatingQuery = EntityQuery(where: .has(FloatingTextComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready, let view = world.arView else { return }
        let dt = context.step

        // Textos flutuantes sobem e desaparecem.
        var expired: [Entity] = []
        for entity in context.all(floatingQuery) {
            guard var floating = entity.components[FloatingTextComponent.self] else { continue }
            floating.life -= dt
            entity.position.y += floating.rise * dt
            let opacity = clamp01(floating.life / (floating.maxLife * 0.4))
            entity.modify(LabelComponent.self) { $0.opacity = opacity }
            entity.components.set(floating)
            if floating.life <= 0 { expired.append(entity) }
        }
        for entity in expired {
            world.recycleText(entity)
        }

        // Projeção para coordenadas de tela, descartando o que está fora da vista.
        let visibleArea = view.bounds.insetBy(dx: -80, dy: -80)
        var labels: [ScreenLabel] = []
        for entity in context.all(labelQuery) {
            guard let label = entity.components[LabelComponent.self], label.visible, entity.isEnabled else { continue }
            let worldPosition = entity.convert(position: label.offset, to: nil)
            guard let point = view.project(worldPosition), visibleArea.contains(point) else { continue }
            labels.append(ScreenLabel(id: entity.id,
                                      text: label.text,
                                      detail: label.detail,
                                      style: label.style,
                                      icon: label.icon,
                                      x: point.x,
                                      y: point.y,
                                      opacity: Double(label.opacity)))
        }
        // Só avisa o SwiftUI quando algo mudou de fato (parado, a tela não é redesenhada à toa).
        if world.state.labels != labels {
            world.state.labels = labels
        }
    }
}
