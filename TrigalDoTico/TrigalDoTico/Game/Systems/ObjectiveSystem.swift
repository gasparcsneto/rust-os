import Foundation
import RealityKit
import simd

/// Mantém sempre um próximo objetivo visível: uma seta 3D quicando sobre o alvo
/// e, quando o alvo está longe, uma seta no chão ao lado do jogador apontando o caminho.
struct ObjectiveSystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready, let player = world.player,
              let targetArrow = world.targetArrow, let groundArrow = world.groundArrow else { return }
        let dt = context.step

        // O objetivo é recalculado algumas vezes por segundo, não a cada quadro.
        world.objectiveTimer -= dt
        if world.objectiveTimer <= 0 {
            world.objectiveTimer = 0.3
            world.objective = world.computeObjective()
        }

        guard let objective = world.objective else {
            targetArrow.isEnabled = false
            groundArrow.isEnabled = false
            return
        }

        let time = world.time
        targetArrow.isEnabled = true
        targetArrow.position = objective.position + Vec3(0, objective.height + sin(time * 5) * 0.2, 0)
        targetArrow.orientation = simd_quatf(angle: time * 2, axis: Vec3(0, 1, 0))

        let playerPosition = player.position
        let delta = (objective.position - playerPosition).xz
        let distance = simd_length(delta)
        if distance > 3.2 {
            let direction = delta / distance
            let reach = 1.35 + sin(time * 6) * 0.12
            groundArrow.isEnabled = true
            groundArrow.position = Vec3(playerPosition.x + direction.x * reach, 0, playerPosition.z + direction.y * reach)
            groundArrow.orientation = simd_quatf(angle: atan2(direction.x, direction.y), axis: Vec3(0, 1, 0))
        } else {
            groundArrow.isEnabled = false
        }
    }
}
