This is an OPCUA server that continuously plays chess against itself and allows a client to monitor the game using variables on a board.

Variables are labelled board.a1, board.a2 etc. through to board.g8. Each variable possesses a value which is one of the following:

    Empty = 0,
    WhitePawn = 1,
    WhiteKnight = 2,
    WhiteBishop = 3,
    WhiteRook = 4,
    WhiteKing = 5,
    WhiteQueen = 6,
    BlackPawn = 7,
    BlackKnight = 8,
    BlackBishop = 9,
    BlackRook = 10,
    BlackKing = 11,
    BlackQueen = 12,

The server requires a UCI compatible chess engine to drive the game but it monitors the game in progress and reflects the game state in the values it exposes to clients.

A client could visualize the game in progress to see something happening.