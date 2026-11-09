import Foundation
import RealityKit
import simd

/// Mantém os itens visuais da pilha das costas iguais à lista lógica,
/// e faz a pilha balançar com o movimento (mola simples).
struct StackSystem: System {
    private let query = EntityQuery(where: .has(CarrierComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for entity in context.all(query) {
            guard var carrier = entity.components[CarrierComponent.self] else { continue }

            // Balanço: a pilha tende a ficar para trás em relação à velocidade.
            if let motion = entity.components[MotionComponent.self] {
                let c = cos(motion.heading)
                let s = sin(motion.heading)
                let local = Vec2(motion.velocity.x * c - motion.velocity.y * s,
                                 motion.velocity.x * s + motion.velocity.y * c)
                let wobble = Vec2(sin(world.time * 5.3), cos(world.time * 4.1)) * 0.02 * simd_length(local)
                let target = -local * GameConfig.Stack.swayPerSpeed + wobble
                let acceleration = (target - carrier.sway) * GameConfig.Stack.swayStiffness
                    - carrier.swayVelocity * GameConfig.Stack.swayDamping
                carrier.swayVelocity += acceleration * dt
                carrier.sway += carrier.swayVelocity * dt
            }

            // Sincroniza os visuais: mantém o prefixo que já bate e refaz o resto.
            let anchor = carrier.anchor
            let visuals = Array(anchor.children)
            var matching = 0
            while matching < visuals.count && matching < carrier.items.count
                    && visuals[matching].components[ItemComponent.self]?.kind == carrier.items[matching] {
                matching += 1
            }
            if matching < visuals.count {
                for index in stride(from: visuals.count - 1, through: matching, by: -1) {
                    world.pool.release(visuals[index])
                }
            }
            let missing = carrier.items.count - matching
            if missing > 0 {
                for index in matching..<carrier.items.count {
                    let item = world.pool.acquire(carrier.items[index])
                    anchor.addChild(item)
                    // Squash & stretch só no item que acabou de pousar
                    // (não quando a pilha encolheu e o topo foi apenas redesenhado).
                    if missing == 1 && carrier.items.count > visuals.count {
                        item.components.set(PopComponent(style: .squash, duration: 0.22, base: Vec3(1, 1, 1)))
                    }
                }
            }

            // Posiciona cada item com o balanço atual.
            var index = 0
            for child in anchor.children {
                child.position = StackLayout.position(index: index, sway: carrier.sway)
                index += 1
            }

            // "MAX" sobre a pilha cheia.
            if carrier.showsMaxLabel {
                let full = carrier.isFull
                let top = min(carrier.items.count, GameConfig.Stack.itemsPerColumn)
                let height = anchor.position.y + Float(top) * GameConfig.Stack.step + 0.45
                entity.modify(LabelComponent.self) {
                    $0.visible = full
                    $0.offset = Vec3(0, height, anchor.position.z)
                }
            }

            entity.components.set(carrier)
        }
    }
}
