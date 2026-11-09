import Foundation
import RealityKit

/// Câmera isométrica fixa: só translada, seguindo o jogador com suavização exponencial.
struct CameraSystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step
        let camera = world.cameraEntity
        let desired = world.cameraPosition(focus: world.cameraFocus())
        let blend = 1 - exp(-GameConfig.Camera.followSharpness * dt)
        camera.position = camera.position + (desired - camera.position) * blend
    }
}
