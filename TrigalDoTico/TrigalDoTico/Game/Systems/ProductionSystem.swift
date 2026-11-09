import Foundation
import RealityKit
import simd

/// Galinheiro e padaria: consomem os montes de entrada e enchem o monte de saída.
struct ProductionSystem: System {
    private let query = EntityQuery(where: .has(ProducerComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for entity in context.all(query) {
            guard var producer = entity.components[ProducerComponent.self],
                  var output = producer.output.components[PileComponent.self] else { continue }

            // Só trabalha se houver ingredientes e espaço na bandeja de saída.
            var canWork = output.count + output.incoming < output.capacity
            if canWork {
                for (index, input) in producer.inputs.enumerated() {
                    let stock = input.components[PileComponent.self]?.count ?? 0
                    if stock < producer.costs[index] {
                        canWork = false
                        break
                    }
                }
            }

            if canWork {
                producer.timer += dt * world.productionSpeed
                if producer.timer >= producer.interval {
                    producer.timer = 0
                    for (index, input) in producer.inputs.enumerated() {
                        let cost = producer.costs[index]
                        input.modify(PileComponent.self) { $0.count -= cost }
                    }

                    let origin = entity.position(relativeTo: nil)
                    world.launch(output.kind,
                                 from: origin + Vec3(0, 0.9, 0.9),
                                 to: producer.output,
                                 offset: output.landingSlot,
                                 receiver: producer.output,
                                 arrival: .pile(1),
                                 duration: 0.45,
                                 arc: 1.2)
                    output.incoming += 1
                    producer.output.components.set(output)
                    producer.model.components.set(PopComponent(style: .squash, duration: 0.3, base: Vec3(1, 1, 1)))

                    // Som só se o jogador estiver por perto.
                    if let player = world.player, simd_distance(player.position, origin) < 9 {
                        world.feedback(.produce)
                    }
                }
            } else {
                producer.timer = min(producer.timer, producer.interval * 0.5)
            }

            entity.components.set(producer)
        }
    }
}
