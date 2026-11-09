import Foundation
import RealityKit
import simd

/// Aplica a velocidade de cada `MotionComponent`, respeitando zonas liberadas e construções.
struct MovementSystem: System {
    private let query = EntityQuery(where: .has(MotionComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for entity in context.all(query) {
            guard var motion = entity.components[MotionComponent.self] else { continue }
            var position = entity.position
            let speed = simd_length(motion.velocity)
            let moving = speed > 0.01
            let radius = motion.radius

            var current = Vec2(position.x, position.z)
            if motion.constrained && !world.isWalkable(current, margin: radius) {
                // Nunca deveria acontecer; se acontecer, volta para um ponto válido em vez de travar.
                current = world.nearestFreeSpot(current, radius: radius)
            }
            var next = current

            if moving {
                let step = motion.velocity * dt
                next = current + step

                // Se o passo inteiro não cabe, desliza ao longo de um dos eixos.
                if motion.constrained && !world.isWalkable(next, margin: radius) {
                    let onlyX = Vec2(current.x + step.x, current.y)
                    let onlyZ = Vec2(current.x, current.y + step.y)
                    if world.isWalkable(onlyX, margin: radius) {
                        next = onlyX
                    } else if world.isWalkable(onlyZ, margin: radius) {
                        next = onlyZ
                    } else {
                        next = current
                    }
                }
            }

            if motion.constrained {
                // Construções empurram para fora, mesmo com o personagem parado
                // (uma construção pode nascer em cima de quem acabou de pagar o pad).
                let pushed = world.resolveColliders(next, radius: radius)
                if pushed != next {
                    if world.isWalkable(pushed, margin: radius) {
                        next = pushed
                    } else if world.isFree(current, radius: radius) {
                        // O empurrão jogaria para fora do mapa (vão estreito entre construção e borda).
                        next = current
                    } else {
                        next = world.nearestFreeSpot(next, radius: radius)
                    }
                }
            }

            position.x = next.x
            position.z = next.y

            if moving {
                let target = atan2(motion.velocity.x, motion.velocity.y)
                motion.heading = lerpAngle(motion.heading, target, min(1, dt * GameConfig.Player.turnSharpness))
            } else if let face = motion.faceHeading {
                motion.heading = lerpAngle(motion.heading, face, min(1, dt * 10))
            }

            position.y = 0
            entity.position = position
            entity.orientation = simd_quatf(angle: motion.heading, axis: Vec3(0, 1, 0))
            entity.components.set(motion)
        }
    }
}
