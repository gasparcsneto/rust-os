import Foundation
import RealityKit
import simd

/// Move os itens em voo num arco com easing e aplica o efeito da chegada.
struct FlightSystem: System {
    private let query = EntityQuery(where: .has(FlightComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step
        var arrived: [Entity] = []

        for entity in context.all(query) {
            guard var flight = entity.components[FlightComponent.self] else { continue }
            flight.elapsed += dt
            let t = min(1, flight.elapsed / max(0.01, flight.duration))

            var end = flight.targetOffset
            if let target = flight.target {
                end = target.convert(position: flight.targetOffset, to: nil)
            }

            let eased = smoothStep(t)
            var position = flight.start + (end - flight.start) * eased
            position.y += sin(t * .pi) * flight.arc
            entity.position = position

            // Cresce no meio do arco e gira até pousar alinhado.
            entity.scale = Vec3(repeating: 1 + 0.3 * sin(t * .pi))
            entity.orientation = simd_quatf(angle: (1 - eased) * 3, axis: Vec3(0, 1, 0))

            entity.components.set(flight)
            if t >= 1 { arrived.append(entity) }
        }

        for entity in arrived {
            guard let flight = entity.components[FlightComponent.self] else { continue }
            switch flight.arrival {
            case .none:
                break
            case .stack(let kind):
                flight.receiver?.modify(CarrierComponent.self) {
                    $0.items.append(kind)
                    $0.incoming = max(0, $0.incoming - 1)
                }
            case .pile(let amount):
                flight.receiver?.modify(PileComponent.self) {
                    $0.count += amount
                    $0.incoming = max(0, $0.incoming - amount)
                }
            case .wallet(let amount):
                world.walletInFlight = max(0, world.walletInFlight - amount)
                world.addMoney(amount)
                world.feedback(.coin)
            }
            world.pool.release(entity)
        }
    }
}
