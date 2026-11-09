import Foundation
import RealityKit
import simd

/// Obstáculos: com o jogador parado por perto, a "vida" cai continuamente,
/// com lascas voando, tremor e som de madeira, até a área ser liberada.
struct ObstacleSystem: System {
    private let query = EntityQuery(where: .has(ObstacleComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready, let player = world.player else { return }
        let dt = context.step
        let playerPosition = player.position
        let playerSpeed = simd_length(player.components[MotionComponent.self]?.velocity ?? .zero)
        let isStill = playerSpeed < GameConfig.Obstacles.stillSpeed
        var destroyed: [Entity] = []

        for obstacle in context.all(query) {
            guard var component = obstacle.components[ObstacleComponent.self] else { continue }
            let center = obstacle.position
            let delta = (center - playerPosition).xz
            let inReach = simd_length(delta) < GameConfig.Obstacles.reach

            if inReach && isStill {
                component.health -= world.obstacleDPS * dt
                component.hitTimer -= dt
                world.save.obstacleHealth[component.id] = max(0, component.health)

                // O jogador vira para o obstáculo.
                let facing = atan2(delta.x, delta.y)
                player.modify(MotionComponent.self) { $0.faceHeading = facing }

                if component.hitTimer <= 0 {
                    component.hitTimer = GameConfig.Obstacles.hitInterval
                    component.shake = 1
                    player.modify(CharacterRigComponent.self) { $0.swing = 1 }
                    world.spawnParticles(.chip, at: center + Vec3(0, 0.7, 0), count: 3, spread: 2.6)
                    world.feedback(.chop)
                }
            } else {
                component.hitTimer = 0
            }

            // Tremor que decai depois de cada batida.
            component.shake = max(0, component.shake - dt * 5)
            let wobble = sin(world.time * 45) * 0.06 * component.shake
            obstacle.orientation = simd_quatf(angle: wobble, axis: Vec3(0, 0, 1))

            obstacle.components.set(component)
            let text = "\(max(0, Int(component.health.rounded(.up))))"
            obstacle.modify(LabelComponent.self) { $0.text = text }

            if component.health <= 0 {
                destroyed.append(obstacle)
            }
        }

        for obstacle in destroyed {
            world.destroyObstacle(obstacle)
        }
    }
}
