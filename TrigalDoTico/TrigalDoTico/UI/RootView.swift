import SwiftUI

/// Empilha a cena 3D, os textos projetados, o joystick, o HUD e os menus.
struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase
    private let state = GameWorld.shared.state

    var body: some View {
        ZStack {
            GameContainerView()
                .ignoresSafeArea()

            LabelsOverlay(state: state)
                .ignoresSafeArea()

            JoystickLayer()
                .ignoresSafeArea()

            HUDView(state: state)

            if state.showMoveHint && !state.showMenu {
                TutorialHintView()
                    .transition(.opacity)
            }

            if state.showMenu {
                MenuView(state: state)
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.25), value: state.showMenu)
        .animation(.easeInOut(duration: 0.25), value: state.showMoveHint)
        .statusBarHidden()
        .persistentSystemOverlays(.hidden)
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                GameWorld.shared.audio.resume()
            } else {
                GameWorld.shared.input = .zero
                GameWorld.shared.saveNow()
            }
        }
    }
}
