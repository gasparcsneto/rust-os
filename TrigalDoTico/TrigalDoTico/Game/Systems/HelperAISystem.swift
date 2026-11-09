import Foundation
import RealityKit
import simd

/// IA dos ajudantes: procura trigo maduro, colhe (via `HarvestSystem`)
/// e leva ao ponto de trigo do balcão quando a pilha enche.
struct HelperAISystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for helper in world.helpers {
            guard var brain = helper.components[HelperComponent.self],
                  let carrier = helper.components[CarrierComponent.self] else { continue }

            let position = helper.position.xz
            var velocity = Vec2.zero
            var face: Float? = nil

            switch brain.state {
            case .seeking:
                brain.thinkTimer -= dt
                if carrier.isFull {
                    brain.state = .delivering
                } else if brain.thinkTimer <= 0 {
                    brain.thinkTimer = 0.4
                    if let index = world.nearestRipeCrop(to: position) {
                        brain.state = .toCrop(index)
                    } else if !carrier.items.isEmpty {
                        brain.state = .delivering
                    }
                }

            case .toCrop(let index):
                if carrier.isFull {
                    brain.state = .delivering
                } else if index >= world.cropRipe.count || !world.cropRipe[index] {
                    // Alguém colheu antes (ou o próprio ajudante, ao chegar perto).
                    brain.state = .seeking
                    brain.thinkTimer = 0
                } else {
                    let delta = world.cropPositions[index] - position
                    let distance = simd_length(delta)
                    if distance > 0.2 {
                        velocity = delta / distance * world.helperSpeed
                    }
                }

            case .delivering:
                let spot = WorldLayout.helperDropSpot(index: brain.index)
                let delta = spot - position
                let distance = simd_length(delta)
                if distance > 0.2 {
                    velocity = delta / distance * min(world.helperSpeed, distance * 5 + 0.5)
                } else {
                    // Parado de frente para o balcão; a entrega é feita pelo `TransferSystem`.
                    face = 0
                    if carrier.items.isEmpty && carrier.incoming == 0 {
                        brain.state = .seeking
                        brain.thinkTimer = 0
                    }
                }
            }

            helper.components.set(brain)
            helper.modify(MotionComponent.self) {
                $0.velocity = velocity
                $0.faceHeading = face
            }
        }
    }
}
