import RealityKit

/// Fecha o quadro: avança o relógio do mundo, copia os contadores para o `GameState`
/// (só quando mudam, para o SwiftUI não redesenhar à toa) e faz o salvamento automático.
struct HUDSyncSystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step
        world.time += dt

        var wheat = 0
        var eggs = 0
        var pies = 0
        if let carrier = world.player?.components[CarrierComponent.self] {
            for item in carrier.items {
                switch item {
                case .wheat: wheat += 1
                case .egg: eggs += 1
                case .pie: pies += 1
                default: break
                }
            }
        }

        let state = world.state
        if state.wheat != wheat { state.wheat = wheat }
        if state.eggs != eggs { state.eggs = eggs }
        if state.pies != pies { state.pies = pies }
        if state.money != world.save.money { state.money = world.save.money }
        if state.hasProgress != world.save.didHarvest { state.hasProgress = world.save.didHarvest }

        world.autosaveTimer += dt
        if world.autosaveTimer >= GameConfig.Persistence.autosaveInterval {
            world.saveNow()
        }
    }
}
