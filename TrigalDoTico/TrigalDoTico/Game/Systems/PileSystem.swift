import RealityKit

/// Mantém os itens visuais de cada monte (balcão, bandejas, tapete do dinheiro)
/// de acordo com a quantidade lógica, usando o pool.
struct PileSystem: System {
    private let query = EntityQuery(where: .has(PileComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }

        for entity in context.all(query) {
            guard let pile = entity.components[PileComponent.self] else { continue }
            let wanted = pile.visuals(for: pile.count)
            var have = entity.children.count
            if have == wanted { continue }

            if have > wanted {
                let visuals = Array(entity.children)
                for index in stride(from: have - 1, through: wanted, by: -1) {
                    world.pool.release(visuals[index])
                }
                continue
            }

            let single = wanted - have == 1
            while have < wanted {
                let item = world.pool.acquire(pile.kind)
                item.position = pile.slot(have)
                entity.addChild(item)
                if single {
                    item.components.set(PopComponent(style: .squash, duration: 0.22, base: Vec3(1, 1, 1)))
                }
                have += 1
            }
        }
    }
}
