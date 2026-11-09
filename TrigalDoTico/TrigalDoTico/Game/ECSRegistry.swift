import RealityKit

/// Registra componentes e sistemas no RealityKit. Precisa rodar uma vez, antes de a cena existir.
/// Os sistemas rodam na ordem em que são registrados aqui.
@MainActor
enum ECSRegistry {
    private static var isRegistered = false

    static func registerAll() {
        guard !isRegistered else { return }
        isRegistered = true

        // Componentes
        PlayerComponent.registerComponent()
        MotionComponent.registerComponent()
        CharacterRigComponent.registerComponent()
        CarrierComponent.registerComponent()
        HarvesterComponent.registerComponent()
        HelperComponent.registerComponent()
        CustomerComponent.registerComponent()
        ChickenComponent.registerComponent()
        ItemComponent.registerComponent()
        FlightComponent.registerComponent()
        PileComponent.registerComponent()
        StationComponent.registerComponent()
        ProducerComponent.registerComponent()
        CropComponent.registerComponent()
        ObstacleComponent.registerComponent()
        PadComponent.registerComponent()
        LabelComponent.registerComponent()
        FloatingTextComponent.registerComponent()
        PopComponent.registerComponent()
        ParticleComponent.registerComponent()

        // Sistemas: decisão → movimento → interação → visuais → câmera/HUD
        PlayerControlSystem.registerSystem()
        HelperAISystem.registerSystem()
        CustomerSystem.registerSystem()
        MovementSystem.registerSystem()
        HarvestSystem.registerSystem()
        CropGrowthSystem.registerSystem()
        TransferSystem.registerSystem()
        ProductionSystem.registerSystem()
        PadSystem.registerSystem()
        ObstacleSystem.registerSystem()
        FlightSystem.registerSystem()
        StackSystem.registerSystem()
        PileSystem.registerSystem()
        CharacterAnimationSystem.registerSystem()
        AmbientAnimationSystem.registerSystem()
        PopSystem.registerSystem()
        DebrisSystem.registerSystem()
        ObjectiveSystem.registerSystem()
        CameraSystem.registerSystem()
        LabelSystem.registerSystem()
        HUDSyncSystem.registerSystem()
    }
}
