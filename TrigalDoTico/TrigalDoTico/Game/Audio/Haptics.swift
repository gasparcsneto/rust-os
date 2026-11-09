import UIKit
import QuartzCore

/// Vibrações leves, com limite de frequência para não virar um zumbido contínuo.
@MainActor
final class Haptics {
    private let light = UIImpactFeedbackGenerator(style: .light)
    private let medium = UIImpactFeedbackGenerator(style: .medium)
    private let notification = UINotificationFeedbackGenerator()
    private var lastTap: CFTimeInterval = 0

    /// Toque leve: coletar, entregar, pagar.
    func tap() {
        let now = CACurrentMediaTime()
        guard now - lastTap > 0.06 else { return }
        lastTap = now
        light.impactOccurred(intensity: 0.7)
    }

    /// Batida um pouco mais forte: cortar madeira.
    func thump() {
        let now = CACurrentMediaTime()
        guard now - lastTap > 0.1 else { return }
        lastTap = now
        medium.impactOccurred(intensity: 0.8)
    }

    /// Construção concluída.
    func success() {
        notification.notificationOccurred(.success)
    }

    /// Sem dinheiro.
    func warning() {
        notification.notificationOccurred(.warning)
    }
}
