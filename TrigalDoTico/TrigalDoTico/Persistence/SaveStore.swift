import Foundation

/// Lê e grava o progresso em um arquivo JSON dentro de Application Support.
enum SaveStore {
    private static let fileName = "trigal-save.json"

    private static var fileURL: URL? {
        let manager = FileManager.default
        guard let folder = try? manager.url(for: .applicationSupportDirectory,
                                            in: .userDomainMask,
                                            appropriateFor: nil,
                                            create: true) else { return nil }
        return folder.appendingPathComponent(fileName)
    }

    /// Carrega o progresso salvo; se não houver arquivo (ou ele estiver ilegível), começa um jogo novo.
    static func load() -> SaveData {
        guard let url = fileURL,
              let data = try? Data(contentsOf: url),
              let save = try? JSONDecoder().decode(SaveData.self, from: data) else {
            return SaveData()
        }
        return save
    }

    static func write(_ save: SaveData) {
        guard let url = fileURL, let data = try? JSONEncoder().encode(save) else { return }
        try? data.write(to: url, options: .atomic)
    }

    static func erase() {
        guard let url = fileURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
