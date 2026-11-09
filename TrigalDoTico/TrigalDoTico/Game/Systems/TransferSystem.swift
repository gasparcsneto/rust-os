import Foundation
import RealityKit
import simd

/// Trocas automáticas por proximidade entre montes e quem carrega:
/// entregar no balcão e nas bandejas, pegar ovos e tortas, recolher dinheiro.
struct TransferSystem: System {
    private let query = EntityQuery(where: .has(StationComponent.self))

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        for station in context.all(query) {
            guard var config = station.components[StationComponent.self],
                  var pile = station.components[PileComponent.self] else { continue }

            config.timer -= dt
            if config.timer > 0 {
                station.components.set(config)
                continue
            }

            let center = station.position(relativeTo: nil).xz
            var acted = false

            for carrierEntity in world.carriers(playerOnly: config.playerOnly) {
                guard simd_distance(carrierEntity.position.xz, center) < config.radius,
                      var carrier = carrierEntity.components[CarrierComponent.self] else { continue }
                let isPlayer = carrierEntity === world.player

                switch config.mode {
                case .deposit:
                    guard pile.count + pile.incoming < pile.capacity,
                          let index = carrier.items.lastIndex(of: pile.kind) else { continue }
                    let from = carrier.anchor.convert(position: StackLayout.position(index: index, sway: carrier.sway), to: nil)
                    carrier.items.remove(at: index)
                    carrierEntity.components.set(carrier)
                    world.launch(pile.kind,
                                 from: from,
                                 to: station,
                                 offset: pile.landingSlot,
                                 receiver: station,
                                 arrival: .pile(1))
                    pile.incoming += 1
                    acted = true
                    if isPlayer { world.feedback(.drop) }

                case .pickup:
                    guard pile.count > 0, !carrier.isFull else { continue }
                    let from = station.convert(position: pile.takeoffSlot, to: nil)
                    pile.count -= 1
                    let slot = carrier.items.count + carrier.incoming
                    world.launch(pile.kind,
                                 from: from,
                                 to: carrier.anchor,
                                 offset: StackLayout.position(index: slot, sway: .zero),
                                 receiver: carrierEntity,
                                 arrival: .stack(pile.kind))
                    carrier.incoming += 1
                    carrierEntity.components.set(carrier)
                    acted = true
                    if isPlayer { world.feedback(.pickup) }

                case .cashCollect:
                    guard pile.count > 0 else { continue }
                    let share = Int((Float(pile.count) * GameConfig.Cash.collectFraction).rounded(.up))
                    let amount = min(pile.count, max(GameConfig.Cash.unitsPerNote, share))
                    let from = station.convert(position: pile.takeoffSlot, to: nil)
                    pile.count -= amount
                    world.launch(.cash,
                                 from: from,
                                 to: carrierEntity,
                                 offset: Vec3(0, 0.8, 0),
                                 arrival: .wallet(amount),
                                 duration: 0.28,
                                 arc: 1.0)
                    world.walletInFlight += amount
                    world.save.didCollectCash = true
                    acted = true
                }
            }

            if acted { config.timer = config.interval }
            station.components.set(config)
            station.components.set(pile)
        }
    }
}
