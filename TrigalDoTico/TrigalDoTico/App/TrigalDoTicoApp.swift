import SwiftUI

@main
struct TrigalDoTicoApp: App {

    init() {
        // Componentes e sistemas precisam estar registrados antes de a cena 3D ser criada.
        ECSRegistry.registerAll()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}
