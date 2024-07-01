This is an OPC UA server that continuously plays chess against itself and allows a client to monitor the game 
using variables on a board.

Chess is played to standard rules with castling and en passant. If the game plays for more than 50 half moves without
a piece being taken or a pawn advanced, the game is reset.

```
cargo run --example chess-server
```

Connect to the server with this url `opc.tcp://localhost:1234`.

Squares on the board are visible in the address space as Board/a1, Board/a2 etc. through to Board/h8. Each variable 
is a byte that possesses a numeric value which is one of the following:

```
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
```

The server requires a UCI compatible chess engine to drive the game. By default the software will launch stockfish from
the current directory but if you supply an argument to the program it will treat that as the path to the engine.

https://stockfishchess.org/download/

A client could visualize the game in progress to see something happening.