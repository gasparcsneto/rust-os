import RealityKit

/// Reaproveita entidades de itens, notas e partículas em vez de criar e destruir a cada uso.
@MainActor
final class EntityPool {
    private var free: [ItemKind: [Entity]] = [:]

    /// Pega uma entidade pronta para uso (transformação zerada, sem pai).
    func acquire(_ kind: ItemKind) -> Entity {
        if let reused = free[kind]?.popLast() {
            reused.transform = Transform()
            reused.isEnabled = true
            return reused
        }
        let created = PropFactory.makeItem(kind)
        created.components.set(ItemComponent(kind: kind))
        return created
    }

    /// Devolve a entidade ao pool, limpando os componentes temporários.
    func release(_ entity: Entity) {
        guard let kind = entity.components[ItemComponent.self]?.kind else {
            entity.removeFromParent()
            return
        }
        entity.removeFromParent()
        entity.components.remove(FlightComponent.self)
        entity.components.remove(PopComponent.self)
        entity.components.remove(ParticleComponent.self)
        free[kind, default: []].append(entity)
    }

    /// Cria entidades com antecedência para evitar engasgos durante o jogo.
    func prewarm(_ kind: ItemKind, count: Int) {
        var created: [Entity] = []
        for _ in 0..<count { created.append(acquire(kind)) }
        for entity in created { release(entity) }
    }
}
