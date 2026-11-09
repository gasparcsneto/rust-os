import RealityKit

extension SceneUpdateContext {
    /// Passo de tempo do quadro, limitado para o jogo não "saltar" depois de um engasgo.
    @MainActor
    var step: Float {
        Float(min(deltaTime, 1.0 / 20.0))
    }

    /// Entidades que casam com a consulta, copiadas para um vetor.
    /// (Copiar permite adicionar e remover entidades durante o laço com segurança.)
    @MainActor
    func all(_ query: EntityQuery) -> [Entity] {
        Array(scene.performQuery(query))
    }
}
