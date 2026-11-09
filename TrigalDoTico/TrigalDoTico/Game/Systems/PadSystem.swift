import Foundation
import RealityKit
import simd

/// Pads de compra: com o jogador em cima, o dinheiro é descontado aos poucos.
/// O pagamento parcial fica guardado; sem dinheiro, aparece "SEM DINHEIRO".
struct PadSystem: System {
    private let query = EntityQuery(where: .has(PadComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready, let player = world.player else { return }
        let dt = context.step
        let playerPosition = player.position
        let half = GameConfig.Pads.size / 2
        var completed: [Entity] = []

        for pad in context.all(query) {
            guard var component = pad.components[PadComponent.self] else { continue }
            let price = component.currentPrice
            let center = pad.position
            let inside = abs(playerPosition.x - center.x) < half && abs(playerPosition.z - center.z) < half

            component.warnCooldown = max(0, component.warnCooldown - dt)
            component.noteTimer = max(0, component.noteTimer - dt)

            if inside {
                component.dwell += dt
            } else {
                component.dwell = 0
                component.payAccumulator = 0
            }

            if inside && component.paid < price && component.dwell >= GameConfig.Pads.startDelay {
                if world.save.money > 0 {
                    let rate = max(GameConfig.Pads.minPayRate, Float(price) / GameConfig.Pads.payDuration)
                    component.payAccumulator += rate * dt
                    let amount = min(Int(component.payAccumulator), price - component.paid, world.save.money)
                    if amount > 0 {
                        component.payAccumulator -= Float(amount)
                        world.spend(amount)
                        component.paid += amount
                        world.save.padPaid[component.kind.rawValue] = component.paid

                        // Notas voando do jogador para o pad (limitadas por tempo).
                        if component.noteTimer <= 0 {
                            component.noteTimer = 0.07
                            world.launch(.cash,
                                         from: playerPosition + Vec3(0, 0.9, 0),
                                         to: pad,
                                         offset: Vec3(0, 0.08, 0),
                                         arrival: .none,
                                         duration: 0.3,
                                         arc: 0.9)
                            world.feedback(.pay)
                        }
                    }
                } else if component.warnCooldown <= 0 {
                    component.warnCooldown = GameConfig.Pads.warnCooldown
                    world.floatText("SEM DINHEIRO", style: .warning, at: center + Vec3(0, 1.9, 0))
                    world.feedback(.deny)
                }
            }

            // Preenchimento verde proporcional ao que já foi pago.
            let progress = max(0.02, min(1, Float(component.paid) / Float(max(1, price))))
            component.progressFill.scale = Vec3(progress, 1, progress)

            pad.components.set(component)

            let remaining = max(0, price - component.paid)
            let detail = component.prices.count > 1
                ? "\(component.kind.title) \(component.level)/\(component.prices.count)"
                : component.kind.title
            pad.modify(LabelComponent.self) {
                $0.text = "\(remaining)"
                $0.detail = detail
            }

            if component.paid >= price {
                completed.append(pad)
            }
        }

        for pad in completed {
            world.completePad(pad)
        }
    }
}
