import Foundation
import RealityKit
import simd

/// Clientes: chegada controlada, filas organizadas, atendimento no balcão,
/// pagamento e saída.
struct CustomerSystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        spawn(world, dt)
        for kind in ItemKind.products {
            updateQueue(world, kind, dt)
        }
        updateLeaving(world)
    }

    /// Chegada de clientes novos, uma fila por produto.
    @MainActor
    private func spawn(_ world: GameWorld, _ dt: Float) {
        for kind in ItemKind.products where world.isQueueOpen(kind) {
            var timer = world.spawnTimers[kind] ?? 0.6
            timer -= dt
            if timer <= 0 {
                if (world.queues[kind]?.count ?? 0) < GameConfig.Customers.maxQueue {
                    world.spawnCustomer(kind)
                }
                timer = GameConfig.Customers.spawnInterval * Float.random(in: 0.7...1.3)
            }
            world.spawnTimers[kind] = timer
        }
    }

    /// Anda cada cliente até o seu lugar e atende o primeiro da fila.
    @MainActor
    private func updateQueue(_ world: GameWorld, _ kind: ItemKind, _ dt: Float) {
        guard let queue = world.queues[kind], !queue.isEmpty else { return }
        let facing = WorldLayout.queueFacing(kind)
        var served: Entity?

        for (index, customer) in queue.enumerated() {
            let spot = WorldLayout.queueSpot(kind, index: index)
            let delta = spot - customer.position.xz
            let distance = simd_length(delta)
            let atSpot = distance < 0.08

            var velocity = Vec2.zero
            if !atSpot {
                velocity = delta / distance * min(GameConfig.Customers.walkSpeed, distance * 6 + 0.4)
            }
            customer.modify(MotionComponent.self) {
                $0.velocity = velocity
                $0.faceHeading = atSpot ? facing : nil
            }

            if index == 0 && atSpot && serve(world, customer, kind, dt) {
                served = customer
            }
        }

        if let served {
            world.sendCustomerAway(served, kind: kind)
        }
    }

    /// Entrega uma unidade por vez ao cliente da frente. Devolve true quando o pedido termina.
    @MainActor
    private func serve(_ world: GameWorld, _ customer: Entity, _ kind: ItemKind, _ dt: Float) -> Bool {
        guard var order = customer.components[CustomerComponent.self],
              let slot = world.slotPiles[kind],
              var pile = slot.components[PileComponent.self] else { return false }

        order.serveTimer -= dt
        var finished = false

        if order.serveTimer <= 0 && pile.count > 0 {
            let from = slot.convert(position: pile.takeoffSlot, to: nil)
            pile.count -= 1
            slot.components.set(pile)
            order.received += 1
            order.serveTimer = GameConfig.Customers.serveInterval

            world.launch(kind,
                         from: from,
                         to: customer,
                         offset: Vec3(0, 0.75, 0.25),
                         arrival: .none,
                         duration: 0.3,
                         arc: 0.7)

            let remaining = order.wanted - order.received
            let text = "\(kind.emoji) \(remaining)"
            customer.modify(LabelComponent.self) { $0.text = text }

            if remaining <= 0 {
                finished = true
                let payout = order.wanted * world.price(of: kind)
                world.spawnCash(amount: payout, from: from)
                world.floatText("+\(payout)", style: .gain, at: customer.position + Vec3(0, 2.0, 0))
                world.feedback(.sell)
                world.save.didSell = true
            }
        }

        customer.components.set(order)
        return finished
    }

    /// Clientes atendidos seguem o caminho de saída e voltam para o pool.
    @MainActor
    private func updateLeaving(_ world: GameWorld) {
        var done: [Entity] = []
        for customer in world.leaving {
            guard var order = customer.components[CustomerComponent.self] else {
                done.append(customer)
                continue
            }
            if order.exitIndex >= order.exitPath.count {
                done.append(customer)
                continue
            }
            let delta = order.exitPath[order.exitIndex] - customer.position.xz
            let distance = simd_length(delta)
            if distance < 0.2 {
                order.exitIndex += 1
                customer.components.set(order)
                continue
            }
            let velocity = delta / distance * GameConfig.Customers.walkSpeed * 1.15
            customer.modify(MotionComponent.self) { $0.velocity = velocity }
        }
        for customer in done {
            world.releaseCustomer(customer)
        }
    }
}
