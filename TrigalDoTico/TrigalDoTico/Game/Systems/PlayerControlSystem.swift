import Foundation
import RealityKit
import simd

/// Converte o joystick em velocidade do jogador.
struct PlayerControlSystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready, let player = world.player else { return }

        var input = world.input
        let magnitude = simd_length(input)
        if magnitude < GameConfig.Controls.deadZone {
            input = .zero
        } else if magnitude > 1 {
            input = input / magnitude
        }

        // A câmera nunca gira: direita da tela = +x, baixo da tela = +z.
        let velocity = input * world.playerSpeed
        let moving = magnitude >= GameConfig.Controls.deadZone
        player.modify(MotionComponent.self) {
            $0.velocity = velocity
            if moving { $0.faceHeading = nil }
        }

        if magnitude > 0.25 && world.state.showMoveHint {
            world.state.showMoveHint = false
            world.save.didMove = true
        }
    }
}
