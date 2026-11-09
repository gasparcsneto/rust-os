import Foundation
import RealityKit
import simd

/// Ceifa automaticamente o trigo maduro perto de quem tem `HarvesterComponent`
/// (jogador e ajudantes) e manda cada espiga voando para a pilha.
struct HarvestSystem: System {
    private let query = EntityQuery(where: .has(HarvesterComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for entity in context.all(query) {
            guard var harvester = entity.components[HarvesterComponent.self] else { continue }
            harvester.cooldown -= dt

            if harvester.cooldown <= 0, var carrier = entity.components[CarrierComponent.self], !carrier.isFull {
                let origin = entity.position.xz
                let reach = harvester.radius * harvester.radius
                let limit = harvester.isPlayer ? GameConfig.Sickle.cropsPerSwing : 1
                var cut = 0
                var index = 0
                let total = world.cropPositions.count

                while index < total && cut < limit && !carrier.isFull {
                    if world.cropRipe[index] {
                        let delta = world.cropPositions[index] - origin
                        if delta.x * delta.x + delta.y * delta.y <= reach {
                            world.harvestCrop(index)
                            let slot = carrier.items.count + carrier.incoming
                            world.launch(.wheat,
                                         from: vec3(world.cropPositions[index], 0.35),
                                         to: carrier.anchor,
                                         offset: StackLayout.position(index: slot, sway: .zero),
                                         receiver: entity,
                                         arrival: .stack(.wheat))
                            carrier.incoming += 1
                            cut += 1
                        }
                    }
                    index += 1
                }

                if cut > 0 {
                    entity.components.set(carrier)
                    harvester.cooldown = harvester.interval
                    entity.modify(CharacterRigComponent.self) { $0.swing = 1 }
                    if harvester.isPlayer {
                        world.feedback(.harvest)
                        world.save.didHarvest = true
                    }
                }
            }

            entity.components.set(harvester)
        }
    }
}
