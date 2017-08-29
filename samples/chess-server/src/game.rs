extern crate uci;

use uci::Engine;

#[derive(Clone, Copy, PartialEq)]
pub enum Square {
    Empty = 0,
    WhitePawn,
    WhiteKnight,
    WhiteBishop,
    WhiteRook,
    WhiteKing,
    WhiteQueen,
    BlackPawn,
    BlackKnight,
    BlackBishop,
    BlackRook,
    BlackKing,
    BlackQueen,
}

impl Square {
    pub fn as_char(&self) -> char {
        match *self {
            Square::Empty => ' ',
            Square::WhitePawn => 'p',
            Square::WhiteKnight => 'n',
            Square::WhiteBishop => 'b',
            Square::WhiteRook => 'r',
            Square::WhiteKing => 'k',
            Square::WhiteQueen => 'q',
            Square::BlackPawn => 'P',
            Square::BlackKnight => 'N',
            Square::BlackBishop => 'B',
            Square::BlackRook => 'R',
            Square::BlackKing => 'K',
            Square::BlackQueen => 'Q',
        }
    }

    pub fn promote_to_queen(&self) -> Square {
        match *self {
            Square::WhitePawn => Square::WhiteQueen,
            Square::BlackPawn => Square::BlackQueen,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }

    pub fn promote_to_rook(&self) -> Square {
        match *self {
            Square::WhitePawn => Square::WhiteRook,
            Square::BlackPawn => Square::BlackRook,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }
    pub fn promote_to_bishop(&self) -> Square {
        match *self {
            Square::WhitePawn => Square::WhiteBishop,
            Square::BlackPawn => Square::BlackBishop,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }

    pub fn promote_to_knight(&self) -> Square {
        match *self {
            Square::WhitePawn => Square::WhiteKnight,
            Square::BlackPawn => Square::BlackKnight,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum File {
    A = 1,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
}

impl File {
    pub fn from_char(c: char) -> File {
        match c {
            'a' | 'A' => File::A,
            'b' | 'B' => File::B,
            'c' | 'C' => File::C,
            'd' | 'D' => File::D,
            'e' | 'E' => File::E,
            'f' | 'F' => File::F,
            'g' | 'G' => File::G,
            'h' | 'H' => File::H,
            _ => panic!("Not a valid file"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Rank {
    R1 = 1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
}

impl Rank {
    pub fn from_char(c: char) -> Rank {
        match c {
            '1' => Rank::R1,
            '2' => Rank::R2,
            '3' => Rank::R3,
            '4' => Rank::R4,
            '5' => Rank::R5,
            '6' => Rank::R6,
            '7' => Rank::R7,
            '8' => Rank::R8,
            _ => panic!("Not a valid rank"),
        }
    }
}

pub struct Game {
    engine: Engine,
    squares: [Square; 64],
}

impl Game {
    pub fn new() -> Game {
        let mut game = Game {
            engine: Engine::new(
                "stockfish_8_x32.exe",
            ).unwrap(),
            squares: [Square::Empty; 64],
        };
        game.engine.set_option("Skill Level", "15").unwrap();

        game.set_square(Rank::R8, File::A, Square::BlackRook);
        game.set_square(Rank::R8, File::B, Square::BlackKnight);
        game.set_square(Rank::R8, File::C, Square::BlackBishop);
        game.set_square(Rank::R8, File::D, Square::BlackQueen);
        game.set_square(Rank::R8, File::E, Square::BlackKing);
        game.set_square(Rank::R8, File::F, Square::BlackBishop);
        game.set_square(Rank::R8, File::G, Square::BlackKnight);
        game.set_square(Rank::R8, File::H, Square::BlackRook);

        game.set_square(Rank::R7, File::A, Square::BlackPawn);
        game.set_square(Rank::R7, File::B, Square::BlackPawn);
        game.set_square(Rank::R7, File::C, Square::BlackPawn);
        game.set_square(Rank::R7, File::D, Square::BlackPawn);
        game.set_square(Rank::R7, File::E, Square::BlackPawn);
        game.set_square(Rank::R7, File::F, Square::BlackPawn);
        game.set_square(Rank::R7, File::G, Square::BlackPawn);
        game.set_square(Rank::R7, File::H, Square::BlackPawn);

        game.set_square(Rank::R2, File::A, Square::WhitePawn);
        game.set_square(Rank::R2, File::B, Square::WhitePawn);
        game.set_square(Rank::R2, File::C, Square::WhitePawn);
        game.set_square(Rank::R2, File::D, Square::WhitePawn);
        game.set_square(Rank::R2, File::E, Square::WhitePawn);
        game.set_square(Rank::R2, File::F, Square::WhitePawn);
        game.set_square(Rank::R2, File::G, Square::WhitePawn);
        game.set_square(Rank::R2, File::H, Square::WhitePawn);

        game.set_square(Rank::R1, File::A, Square::WhiteRook);
        game.set_square(Rank::R1, File::B, Square::WhiteKnight);
        game.set_square(Rank::R1, File::C, Square::WhiteBishop);
        game.set_square(Rank::R1, File::D, Square::WhiteQueen);
        game.set_square(Rank::R1, File::E, Square::WhiteKing);
        game.set_square(Rank::R1, File::F, Square::WhiteBishop);
        game.set_square(Rank::R1, File::G, Square::WhiteKnight);
        game.set_square(Rank::R1, File::H, Square::WhiteRook);

        game
    }

    pub fn square_from_str(&self, coord: &str) -> Square {
        self.squares[Self::rank_file_str_index(coord)]
    }

    pub fn set_square(&mut self, rank: Rank, file: File, value: Square) {
        if (rank as u8) < 1 || rank as u8 > 8 {
            panic!("Not a valid Rank")
        }
        self.squares[Self::rank_file_index(rank, file)] = value;
    }


    pub fn bestmove(&self) -> uci::Result<String> {
        self.engine.bestmove()
    }

    pub fn make_move(&mut self, m: String) {
        let from_idx = Self::rank_file_str_index(&m[..2]);
        let to_idx = Self::rank_file_str_index(&m[2..4]);

        let piece = self.squares[from_idx];

        // Check for pawn promotion
        if m.len() == 5 {
            let action = m[5..6].chars().next().unwrap();
            match action {
                'q' => {
                    self.squares[to_idx] = piece.promote_to_queen();
                    self.squares[from_idx] = Square::Empty;
                }
                'r' => {
                    self.squares[to_idx] = piece.promote_to_rook();
                    self.squares[from_idx] = Square::Empty;
                }
                'b' => {
                    self.squares[to_idx] = piece.promote_to_bishop();
                    self.squares[from_idx] = Square::Empty;
                }
                'n' => {
                    self.squares[to_idx] = piece.promote_to_knight();
                    self.squares[from_idx] = Square::Empty;
                }
                _ => panic!("Unrecognized action"),
            }
        } else {
            self.squares[to_idx] = self.squares[from_idx];
            self.squares[from_idx] = Square::Empty;
        }

        // Castling - assumption is the chess program wouldn't have allowed
        // this move if it wasn't legal
        if piece == Square::BlackKing || piece == Square::WhiteKing {
            let (r1, f1) = Self::rank_file(&m[..2]);
            let (_, f2) = Self::rank_file(&m[2..4]);

            // Now move the rook
            if ((f1 as i32) - (f2 as i32)).abs() > 1 {
                let rook_piece = if piece == Square::BlackKing {
                    Square::BlackRook
                } else {
                    Square::WhiteRook
                };
                if (f1 as i32) < (f2 as i32) {
                    self.squares[Self::rank_file_str_index(&format!("f{}", r1 as usize))] =
                        rook_piece;
                    self.squares[Self::rank_file_str_index(&format!("h{}", r1 as usize))] =
                        Square::Empty;
                } else if (f1 as i32) > (f2 as i32) {
                    self.squares[Self::rank_file_str_index(&format!("d{}", r1 as usize))] =
                        rook_piece;
                    self.squares[Self::rank_file_str_index(&format!("a{}", r1 as usize))] =
                        Square::Empty;
                }
            }
        }

        let _ = self.engine.make_moves(&vec![m]);
    }

    pub fn rank_file(coord: &str) -> (Rank, File) {
        let mut chars = coord.chars();
        let file = File::from_char(chars.next().unwrap());
        let rank = Rank::from_char(chars.next().unwrap());
        (rank, file)
    }

    pub fn rank_file_index(rank: Rank, file: File) -> usize {
        (file as usize - 1) + (rank as usize - 1) * 8
    }

    pub fn rank_file_str_index(s: &str) -> usize {
        if s.len() != 2 {
            panic!("Coord should be file, rank");
        }
        let (rank, file) = Self::rank_file(s);
        Self::rank_file_index(rank, file)
    }

    pub fn print_board(&self) {
        let mut line = String::new();

        for idx in 0..self.squares.len() {
            if idx % 8 == 0 && !line.is_empty() {
                println!("{}", line);
                line.clear();
            }
            line.push(self.squares[idx].as_char());
        }
        println!("{}", line);
    }
}
