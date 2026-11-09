import Foundation
import RealityKit
import simd

/// Animação procedural dos bonecos: balanço de pernas e braços ao andar,
/// respiração parado e o golpe da foice.
struct CharacterAnimationSystem: System {
    private let query = EntityQuery(where: .has(CharacterRigComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard GameWorld.ready != nil else { return }
        let dt = context.step
        let xAxis = Vec3(1, 0, 0)

        for entity in context.all(query) {
            guard var rig = entity.components[CharacterRigComponent.self] else { continue }
            let speed = simd_length(entity.components[MotionComponent.self]?.velocity ?? .zero)
            let moving = speed > 0.15

            rig.phase += dt * (moving ? 6 + speed * 2.2 : 2.2)
            let wave = sin(rig.phase)
            let amplitude: Float = moving ? min(0.9, 0.35 + speed * 0.12) : 0

            rig.legLeft.orientation = simd_quatf(angle: wave * amplitude, axis: xAxis)
            rig.legRight.orientation = simd_quatf(angle: -wave * amplitude, axis: xAxis)
            rig.armLeft.orientation = simd_quatf(angle: -wave * amplitude * 0.8, axis: xAxis)

            var rightArm = wave * amplitude * 0.8
            if rig.swing > 0 {
                // Golpe: o braço direito sobe para a frente e desce.
                rig.swing = max(0, rig.swing - dt * 5)
                rightArm = -0.3 - 1.7 * sin(rig.swing * .pi)
            }
            rig.armRight.orientation = simd_quatf(angle: rightArm, axis: xAxis)

            // Sobe e desce ao andar; respira quando parado.
            rig.body.position.y = moving ? abs(wave) * 0.06 : wave * 0.015

            entity.components.set(rig)
        }
    }
}

/// Animações de ambiente: galinhas ciscando no terreiro.
struct AmbientAnimationSystem: System {
    private let query = EntityQuery(where: .has(ChickenComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard GameWorld.ready != nil else { return }
        let dt = context.step

        for chicken in context.all(query) {
            guard var component = chicken.components[ChickenComponent.self] else { continue }
            component.phase += dt
            let p = component.phase

            // Passeio em curva fechada ao redor do ponto de origem, com pulinhos.
            let offset = Vec3(cos(p * 0.6) * 0.42, abs(sin(p * 5)) * 0.05, sin(p * 0.83) * 0.22)
            chicken.position = component.home + offset

            // Olha para onde anda e bica o chão de vez em quando.
            let dx = -sin(p * 0.6) * 0.6 * 0.42
            let dz = cos(p * 0.83) * 0.83 * 0.22
            let peck = pow(max(0, sin(p * 2.1)), 8) * 0.7
            chicken.orientation = simd_quatf(angle: atan2(dx, dz), axis: Vec3(0, 1, 0))
                * simd_quatf(angle: peck, axis: Vec3(1, 0, 0))

            chicken.components.set(component)
        }
    }
}

/// Animações curtas de escala: surgir, pousar (squash & stretch), amadurecer e sumir.
struct PopSystem: System {
    private let query = EntityQuery(where: .has(PopComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard GameWorld.ready != nil else { return }
        let dt = context.step

        for entity in context.all(query) {
            guard var pop = entity.components[PopComponent.self] else { continue }
            pop.elapsed += dt
            let t = clamp01(pop.elapsed / max(0.01, pop.duration))

            switch pop.style {
            case .grow:
                entity.scale = pop.base * max(0.001, easeOutBack(t))
            case .squash:
                let k = sin(t * .pi)
                entity.scale = pop.base * Vec3(1 + 0.28 * k, 1 - 0.32 * k, 1 + 0.28 * k)
            case .bounce:
                let k = sin(t * .pi)
                entity.scale = pop.base * Vec3(1 + 0.12 * k, 1 + 0.25 * k, 1 + 0.12 * k)
            case .shrink:
                entity.scale = pop.base * max(0.001, 1 - t * t)
            }

            if t >= 1 {
                entity.components.remove(PopComponent.self)
                switch pop.finish {
                case .none:
                    entity.scale = pop.base
                case .remove:
                    entity.removeFromParent()
                }
            } else {
                entity.components.set(pop)
            }
        }
    }
}

/// Partículas de palha e lascas: gravidade, quique no chão, giro e sumiço.
struct DebrisSystem: System {
    private let query = EntityQuery(where: .has(ParticleComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for particle in context.all(query) {
            guard var component = particle.components[ParticleComponent.self] else { continue }
            component.life -= dt
            if component.life <= 0 {
                world.releaseParticle(particle)
                continue
            }

            component.velocity.y -= 13 * dt
            var position = particle.position + component.velocity * dt
            if position.y < 0.05 {
                position.y = 0.05
                component.velocity = Vec3(component.velocity.x * 0.4, -component.velocity.y * 0.3, component.velocity.z * 0.4)
            }
            particle.position = position

            let spinSpeed = simd_length(component.spin)
            if spinSpeed > 0.001 {
                particle.orientation = particle.orientation * simd_quatf(angle: spinSpeed * dt, axis: component.spin / spinSpeed)
            }
            particle.scale = Vec3(repeating: min(1, component.life / 0.2))
            particle.components.set(component)
        }
    }
}
