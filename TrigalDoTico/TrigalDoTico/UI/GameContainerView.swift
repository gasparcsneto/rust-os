import SwiftUI
import RealityKit

/// Cena 3D do jogo: uma `ARView` em modo não-AR (câmera virtual, sem usar a câmera do aparelho).
struct GameContainerView: UIViewRepresentable {

    func makeUIView(context: Context) -> ARView {
        let view = ARView(frame: .zero, cameraMode: .nonAR, automaticallyConfigureSession: false)
        GameWorld.shared.attach(to: view)
        return view
    }

    func updateUIView(_ uiView: ARView, context: Context) {}
}
