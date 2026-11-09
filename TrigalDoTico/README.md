# Trigal do Tico

Jogo idle arcade de fazenda para iPhone (retrato), feito com RealityKit + SwiftUI em Swift 6.
Arte, nome e personagens são originais; todos os modelos são montados em código com primitivas low-poly e não há nenhum asset externo (nem imagens, nem áudio).

## Como rodar

1. Abra `TrigalDoTico.xcodeproj` no **Xcode 16 ou mais novo** (o projeto usa pastas sincronizadas e Swift 6).
2. Escolha um simulador de iPhone com iOS 18+ e rode (⌘R).
3. Para rodar em um aparelho, selecione o seu *Team* em *Signing & Capabilities* e, se quiser, troque o bundle id `com.example.TrigalDoTico`.

O jogo não usa a câmera: a `ARView` roda em modo `.nonAR`, com câmera virtual. Haptics só funcionam em aparelho real.

Se as cores parecerem escuras ou estouradas no seu aparelho, ajuste `GameConfig.Visual.sunIntensity`.

## Como se joga

- Arraste o dedo em qualquer lugar: o joystick aparece ali e o personagem anda. Tudo o mais é automático por proximidade.
- Passe pelo trigo para colher, chegue perto do balcão azul para entregar, pise no tapete verde para recolher o dinheiro.
- Fique parado ao lado de um obstáculo para cortá-lo e liberar a área.
- Fique em cima de um pad (quadrado tracejado) para pagar. O pagamento começa depois de um instante parado ali (`GameConfig.Pads.startDelay`), para não gastar só de passar por cima. Pagamento parcial fica guardado.
- A seta amarela sempre mostra o próximo objetivo.

Ordem de progressão: trigo → tronco (libera o campo oeste) → ajudantes (até 4) → foice → galinheiro (ovos) → padaria (tortas) → celeiro e ampliações → árvore seca (norte: botas e forno turbo) → destroços (noroeste: treino e promoção).

## Arquitetura

```
TrigalDoTico/
  App/           ponto de entrada (registra o ECS)
  Config/        GameConfig.swift (balanceamento) e WorldLayout.swift (mapa)
  Persistence/   SaveData (Codable) e SaveStore (arquivo JSON)
  UI/            SwiftUI: cena, joystick, HUD, textos projetados, menu, tutorial
  Game/
    GameWorld*.swift   recursos compartilhados, montagem da cena e regras de progressão
    GameState.swift    estado @Observable lido pelo HUD
    ECSRegistry.swift  registro de componentes e sistemas (define a ordem de execução)
    Components/        dados puros
    Systems/           lógica quadro a quadro
    Entities/          MeshBuilder, fábricas de modelos e pool
    Audio/             sons sintetizados (AVAudioEngine) e haptics
    Support/           tipos e matemática
```

### Ideias centrais

- **ECS do RealityKit.** Componentes são structs só com dados. Toda a lógica de quadro está em `System`s. `GameWorld` faz o papel de "resources": guarda referências de cena, pool, save, entrada do joystick e os valores derivados de upgrades. Os sistemas escrevem no `GameState`, e o SwiftUI só lê.
- **Tudo é monte, pilha ou voo.** `PileComponent` é um monte de itens iguais (balcão, bandejas, tapete do dinheiro). `CarrierComponent` é a pilha nas costas. `FlightComponent` leva um item em arco de um para o outro e aplica o efeito na chegada. A contagem lógica é separada do visual: `PileSystem` e `StackSystem` só espelham os números usando o pool.
- **Estações.** `StationComponent` liga um monte a quem carrega: `deposit` (costas → monte), `pickup` (monte → costas) e `cashCollect` (dinheiro → carteira). Não há botão de ação em lugar nenhum.
- **Produção.** `ProducerComponent` consome montes de entrada e enche um monte de saída. Galinheiro e padaria são só configurações diferentes dele.
- **Textos.** `LabelComponent` marca um texto preso a uma entidade. O `LabelSystem` projeta a posição na tela e o SwiftUI desenha (balões, preços, vida, "MAX", "+12", "SEM DINHEIRO").
- **Modelos.** `MeshBuilder` gera malhas facetadas com várias cores numa única entidade. Malhas e materiais ficam em cache em `ModelFactory`.
- **Desempenho.** Pool para itens, notas, partículas, clientes e textos flutuantes; plantação em vetores paralelos (posição e "maduro") para a colheita não consultar componentes; só o trigo em rebrota é atualizado; limite de partículas.

### Sistemas (na ordem em que rodam)

| Sistema | Função |
|---|---|
| `PlayerControlSystem` | joystick → velocidade do jogador |
| `HelperAISystem` | ajudantes: procurar trigo, colher, entregar |
| `CustomerSystem` | chegada, filas, atendimento, pagamento e saída |
| `MovementSystem` | aplica velocidade, zonas liberadas e colisão com construções |
| `HarvestSystem` | ceifa por proximidade e manda o trigo para a pilha |
| `CropGrowthSystem` | rebrota do trigo |
| `TransferSystem` | entregas, retiradas e coleta de dinheiro |
| `ProductionSystem` | galinheiro e padaria |
| `PadSystem` | pagamento gradual dos pads |
| `ObstacleSystem` | corte dos obstáculos |
| `FlightSystem` | arcos dos itens e efeito da chegada |
| `StackSystem` | pilha das costas e balanço |
| `PileSystem` | visuais dos montes |
| `CharacterAnimationSystem` | caminhada, respiração e golpe |
| `AmbientAnimationSystem` | galinhas |
| `PopSystem` | squash & stretch, surgir e sumir |
| `DebrisSystem` | palha e lascas |
| `ObjectiveSystem` | setas de objetivo |
| `CameraSystem` | câmera isométrica que segue o jogador |
| `LabelSystem` | projeção dos textos na tela |
| `HUDSyncSystem` | contadores do HUD e salvamento automático |

A ordem vem do registro em `ECSRegistry.registerAll()`. Nenhum sistema depende de rodar exatamente antes de outro: no pior caso, um efeito aparece um quadro depois.

### Persistência

`SaveStore` grava um JSON em Application Support com dinheiro, zonas liberadas, vida dos obstáculos, nível e pagamento parcial de cada pad, estoque do balcão e das bandejas, a pilha das costas do jogador, dinheiro no tapete e marcos do tutorial. Salva a cada 5 s, ao concluir compras ou obstáculos e quando o app sai do primeiro plano. Itens e notas em voo contam como já entregues.

A leitura é tolerante (`SaveData.init(from:)`): campo ausente no arquivo fica com o valor padrão. Ao criar um campo novo em `SaveData`, acrescente-o também em `CodingKeys` e em `init(from:)`; assim um save antigo continua valendo.

## Balanceamento

Todos os números estão em `Config/GameConfig.swift`, comentados. As posições do mapa (zonas, campos, obstáculos, pads, filas) estão em `Config/WorldLayout.swift`.

## Como adicionar um novo produto

Exemplo: queijo.

1. `Game/Support/GameTypes.swift`: adicione `case cheese` em `ItemKind`, inclua em `products` e preencha `emoji`, `pileSpacing` e `pileLayerHeight`.
2. `Game/Entities/PropFactory.swift`: desenhe o item em `makeItem` e acrescente a placa dele no balcão se a posição ficar fora do L atual.
3. `Config/GameConfig.swift`: preço em `Customers.basePrice` e quantidade pedida em `Customers.wantedRange`.
4. `Config/WorldLayout.swift`: `slotPosition`, `queueSpot`, `queueFacing`, `customerSpawn` e `customerExit` para a nova fila.
5. `Game/GameWorld+Progression.swift`: em `isQueueOpen`, diga quando a fila abre.
6. HUD: some o item em `HUDSyncSystem`, crie o campo em `GameState` e adicione um `CounterPill` em `HUDView`.

## Como adicionar uma nova construção

Exemplo: queijaria que transforma ovos em queijo.

1. `Config/WorldLayout.swift`: adicione `case dairy` em `PadKind` (com `title` e `doneText`), um ponto `dairySite` e um `PadDef` em `pads` com posição, requisitos e preço. A posição na lista define quando a seta de objetivo aponta para ele.
2. `Config/GameConfig.swift`: crie `enum Dairy` com preço, custo, intervalo e capacidades.
3. `Game/Entities/PropFactory.swift`: crie `makeDairy()` com o modelo.
4. `Game/GameWorld+Build.swift`: crie `buildDairy(animated:)` copiando `buildCoop`: modelo, estações de entrada (`deposit`) e saída (`pickup`) via `makeStation`, um `ProducerComponent` e um `Collider`. Chame-a em `buildWorld()` quando `level(.dairy) > 0`.
5. `Game/GameWorld+Progression.swift`: trate `.dairy` no `switch` de `completePad`.
6. `UI/LabelsOverlay.swift`: escolha o ícone em `PadIconView`.

Um pad que é só upgrade (sem construção) precisa apenas dos passos 1 e 6 e de uma linha em `applyUpgrades()`.
