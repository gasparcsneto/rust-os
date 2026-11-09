import RealityKit

/// Faz o trigo cortado crescer de novo. Percorre só os pés em rebrota
/// (lista `growing` do mundo), não a plantação inteira.
struct CropGrowthSystem: System {

    @MainActor
    init(scene: RealityKit.Scene) {}

    @MainActor
    func update(context: SceneUpdateContext) {
        guard let world = GameWorld.ready else { return }
        let dt = context.step

        var cursor = 0
        while cursor < world.growing.count {
            let index = world.growing[cursor]
            let crop = world.crops[index]
            guard var component = crop.components[CropComponent.self] else {
                world.growing.remove(at: cursor)
                continue
            }

            component.timer -= dt
            if component.timer <= 0 {
                component.isRipe = true
                component.timer = 0
                crop.components.set(component)
                world.cropRipe[index] = true
                crop.components.set(PopComponent(style: .bounce, duration: 0.3, base: Vec3(1, 1, 1)))
                world.growing.swapAt(cursor, world.growing.count - 1)
                world.growing.removeLast()
                continue
            }

            crop.scale = CropVisual.scale(progress: 1 - component.timer / max(0.01, component.duration))
            crop.components.set(component)
            cursor += 1
        }
    }
}
