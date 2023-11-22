// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use uci::Engine;

/// The piece on a square
#[derive(Clone, Copy, PartialEq)]
pub enum Piece {
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

impl Piece {
    pub fn as_char(&self) -> char {
        match self {
            Piece::Empty => ' ',
            Piece::WhitePawn => 'P',
            Piece::WhiteKnight => 'N',
            Piece::WhiteBishop => 'B',
            Piece::WhiteRook => 'R',
            Piece::WhiteKing => 'K',
            Piece::WhiteQueen => 'Q',
            Piece::BlackPawn => 'p',
            Piece::BlackKnight => 'n',
            Piece::BlackBishop => 'b',
            Piece::BlackRook => 'r',
            Piece::BlackKing => 'k',
            Piece::BlackQueen => 'q',
        }
    }

    pub fn promote_to_queen(&self) -> Piece {
        match self {
            Piece::WhitePawn => Piece::WhiteQueen,
            Piece::BlackPawn => Piece::BlackQueen,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }

    pub fn promote_to_rook(&self) -> Piece {
        match self {
            Piece::WhitePawn => Piece::WhiteRook,
            Piece::BlackPawn => Piece::BlackRook,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }
    pub fn promote_to_bishop(&self) -> Piece {
        match self {
            Piece::WhitePawn => Piece::WhiteBishop,
            Piece::BlackPawn => Piece::BlackBishop,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }

    pub fn promote_to_knight(&self) -> Piece {
        match self {
            Piece::WhitePawn => Piece::WhiteKnight,
            Piece::BlackPawn => Piece::BlackKnight,
            _ => panic!("This is not a pawn and cannot be promoted"),
        }
    }
}

// File - letter of the square. The index is used for turning file to an array offset
#[derive(Clone, Copy, PartialEq)]
pub enum File {
    A = 0,
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

    pub fn as_char(&self) -> char {
        match self {
            File::A => 'a',
            File::B => 'b',
            File::C => 'c',
            File::D => 'd',
            File::E => 'e',
            File::F => 'f',
            File::G => 'g',
            File::H => 'h',
        }
    }
}

// Ranks - digit of the square. The index goes downwards from the top of the board.
#[derive(Clone, Copy, PartialEq)]
pub enum Rank {
    R8 = 0,
    R7,
    R6,
    R5,
    R4,
    R3,
    R2,
    R1,
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

    pub fn as_char(&self) -> char {
        match self {
            Rank::R1 => '1',
            Rank::R2 => '2',
            Rank::R3 => '3',
            Rank::R4 => '4',
            Rank::R5 => '5',
            Rank::R6 => '6',
            Rank::R7 => '7',
            Rank::R8 => '8',
        }
    }
}

/// Game manages the general game state and controls the engine.
pub struct Game {
    /// The chess engine backend
    engine: Engine,
    /// The squares of the board, each being empty or occupied by a piece
    squares: [Piece; 64],
    /// Flag indicating if white is to play
    pub white_to_play: bool,
    /// Number of full white, black moves
    pub full_move: u32,
    /// Number of half moves since the last capture or pawn advance
    pub half_move_clock: u32,
    /// Last move if any
    pub last_move: Option<String>,
    /// Flags controlling castling
    white_can_castle_queenside: bool,
    white_can_castle_kingside: bool,
    black_can_castle_queenside: bool,
    black_can_castle_kingside: bool,
    /// The rank, file for the last pawn to move 2 spaces
    en_passant: Option<(Rank, File)>,
}

impl Game {
    pub fn new(path: &str) -> Game {
        let engine = Engine::new(path).unwrap();

        let mut game = Game {
            engine: engine.movetime(200),
            squares: [Piece::Empty; 64],
            white_to_play: true,
            full_move: 0,
            half_move_clock: 0,
            white_can_castle_queenside: true,
            white_can_castle_kingside: true,
            black_can_castle_queenside: true,
            black_can_castle_kingside: true,
            en_passant: None,
            last_move: None,
        };
        game.reset();
        game
    }

    pub fn reset(&mut self) {
        self.white_to_play = true;
        self.full_move = 0;
        self.half_move_clock = 0;
        self.squares = [Piece::Empty; 64];
        self.white_can_castle_queenside = true;
        self.white_can_castle_kingside = true;
        self.black_can_castle_queenside = true;
        self.black_can_castle_kingside = true;
        self.en_passant = None;
        self.last_move = None;

        self.set_square(Rank::R8, File::A, Piece::BlackRook);
        self.set_square(Rank::R8, File::B, Piece::BlackKnight);
        self.set_square(Rank::R8, File::C, Piece::BlackBishop);
        self.set_square(Rank::R8, File::D, Piece::BlackQueen);
        self.set_square(Rank::R8, File::E, Piece::BlackKing);
        self.set_square(Rank::R8, File::F, Piece::BlackBishop);
        self.set_square(Rank::R8, File::G, Piece::BlackKnight);
        self.set_square(Rank::R8, File::H, Piece::BlackRook);

        self.set_square(Rank::R7, File::A, Piece::BlackPawn);
        self.set_square(Rank::R7, File::B, Piece::BlackPawn);
        self.set_square(Rank::R7, File::C, Piece::BlackPawn);
        self.set_square(Rank::R7, File::D, Piece::BlackPawn);
        self.set_square(Rank::R7, File::E, Piece::BlackPawn);
        self.set_square(Rank::R7, File::F, Piece::BlackPawn);
        self.set_square(Rank::R7, File::G, Piece::BlackPawn);
        self.set_square(Rank::R7, File::H, Piece::BlackPawn);

        self.set_square(Rank::R2, File::A, Piece::WhitePawn);
        self.set_square(Rank::R2, File::B, Piece::WhitePawn);
        self.set_square(Rank::R2, File::C, Piece::WhitePawn);
        self.set_square(Rank::R2, File::D, Piece::WhitePawn);
        self.set_square(Rank::R2, File::E, Piece::WhitePawn);
        self.set_square(Rank::R2, File::F, Piece::WhitePawn);
        self.set_square(Rank::R2, File::G, Piece::WhitePawn);
        self.set_square(Rank::R2, File::H, Piece::WhitePawn);

        self.set_square(Rank::R1, File::A, Piece::WhiteRook);
        self.set_square(Rank::R1, File::B, Piece::WhiteKnight);
        self.set_square(Rank::R1, File::C, Piece::WhiteBishop);
        self.set_square(Rank::R1, File::D, Piece::WhiteQueen);
        self.set_square(Rank::R1, File::E, Piece::WhiteKing);
        self.set_square(Rank::R1, File::F, Piece::WhiteBishop);
        self.set_square(Rank::R1, File::G, Piece::WhiteKnight);
        self.set_square(Rank::R1, File::H, Piece::WhiteRook);
    }

    pub fn square_from_str(&self, coord: &str) -> Piece {
        self.squares[Self::rank_file_str_index(coord)]
    }

    pub fn set_square(&mut self, rank: Rank, file: File, value: Piece) {
        self.squares[Self::rank_file_index(rank, file)] = value;
    }

    fn fen_rank(&self, rank: Rank) -> String {
        let rank_idx = rank as usize * 8;
        let squares = &self.squares[rank_idx..(rank_idx + 8)];

        let mut result = String::with_capacity(8);
        let mut empty = 0;
        for square in squares {
            if *square == Piece::Empty {
                empty += 1;
            } else {
                if empty != 0 {
                    result.push_str(&format!("{}", empty));
                    empty = 0;
                }
                result.push(square.as_char());
            }
        }
        if empty != 0 {
            result.push_str(&format!("{}", empty));
        }
        result
    }

    pub fn as_fen(&self) -> String {
        let mut result = String::with_capacity(80);

        let ranks = [
            Rank::R8,
            Rank::R7,
            Rank::R6,
            Rank::R5,
            Rank::R4,
            Rank::R3,
            Rank::R2,
            Rank::R1,
        ];
        for r in ranks.iter() {
            result.push_str(&self.fen_rank(*r));
            result.push(if *r != Rank::R1 { '/' } else { ' ' });
        }

        // Player to move
        result.push(if self.white_to_play { 'w' } else { 'b' });

        // Castling requires this code tracks whether rooks or kings were moved in the game
        result.push(' ');

        let mut castle = String::with_capacity(4);
        if self.white_can_castle_kingside {
            castle.push('K');
        }
        if self.white_can_castle_queenside {
            castle.push('Q');
        }
        if self.black_can_castle_kingside {
            castle.push('k');
        }
        if self.black_can_castle_queenside {
            castle.push('q');
        }
        if castle.is_empty() {
            castle.push('-');
        }
        result.push_str(&castle);

        result.push(' ');

        // Disabling en passant.
        if let Some(ref en_passant) = self.en_passant {
            let (rank, file) = *en_passant;
            result.push(file.as_char());
            result.push(rank.as_char());
        } else {
            result.push_str("-");
        }
        result.push(' ');

        result.push_str(&format!("{} ", self.half_move_clock));
        result.push_str(&format!("{}", self.full_move));
        result
    }

    pub fn set_position(&self) {
        let fen = self.as_fen();
        println!("Setting position {}", fen);
        let _ = self.engine.set_position(&fen);
    }

    pub fn bestmove(&self) -> uci::Result<String> {
        self.engine.bestmove()
    }

    pub fn make_move(&mut self, m: String) {
        let from_idx = Self::rank_file_str_index(&m[..2]);
        let to_idx = Self::rank_file_str_index(&m[2..4]);

        let piece_to_move = self.squares[from_idx];

        self.half_move_clock += 1;
        self.en_passant = None;

        // Pawn advance reset half_move_clock
        if piece_to_move == Piece::WhitePawn || piece_to_move == Piece::BlackPawn {
            self.half_move_clock = 0;

            let (r1, f1) = Self::rank_file(&m[..2]);
            let (r2, _) = Self::rank_file(&m[2..4]);

            // En passant test.
            if r1 == Rank::R2 && r2 == Rank::R4 {
                self.en_passant = Some((Rank::R3, f1));
            } else if r1 == Rank::R7 && r2 == Rank::R5 {
                self.en_passant = Some((Rank::R6, f1));
            }
        }

        // Check for pawn promotion
        if m.len() == 5 {
            let action = m[4..5].chars().next().unwrap();
            match action {
                'q' => {
                    self.squares[to_idx] = piece_to_move.promote_to_queen();
                    self.squares[from_idx] = Piece::Empty;
                }
                'r' => {
                    self.squares[to_idx] = piece_to_move.promote_to_rook();
                    self.squares[from_idx] = Piece::Empty;
                }
                'b' => {
                    self.squares[to_idx] = piece_to_move.promote_to_bishop();
                    self.squares[from_idx] = Piece::Empty;
                }
                'n' => {
                    self.squares[to_idx] = piece_to_move.promote_to_knight();
                    self.squares[from_idx] = Piece::Empty;
                }
                _ => panic!("Unrecognized action"),
            }
        } else {
            // Castling - if king moves more than one space to the side
            if piece_to_move == Piece::BlackKing || piece_to_move == Piece::WhiteKing {
                self.squares[to_idx] = self.squares[from_idx];
                self.squares[from_idx] = Piece::Empty;

                let (r1, f1) = Self::rank_file(&m[..2]);
                let (_, f2) = Self::rank_file(&m[2..4]);

                // Now move the rook
                if ((f1 as i32) - (f2 as i32)).abs() > 1 {
                    let rook_piece = if piece_to_move == Piece::BlackKing {
                        self.black_can_castle_kingside = false;
                        self.black_can_castle_queenside = false;
                        Piece::BlackRook
                    } else {
                        self.white_can_castle_kingside = false;
                        self.white_can_castle_queenside = false;
                        Piece::WhiteRook
                    };
                    if (f1 as i32) < (f2 as i32) {
                        self.squares[Self::rank_file_str_index(&format!("f{}", r1.as_char()))] =
                            rook_piece;
                        self.squares[Self::rank_file_str_index(&format!("h{}", r1.as_char()))] =
                            Piece::Empty;
                    } else if (f1 as i32) > (f2 as i32) {
                        self.squares[Self::rank_file_str_index(&format!("d{}", r1.as_char()))] =
                            rook_piece;
                        self.squares[Self::rank_file_str_index(&format!("a{}", r1.as_char()))] =
                            Piece::Empty;
                    }
                }
            } else {
                // If the piece being moved is a king or rook we have to disable castling options
                match piece_to_move {
                    Piece::BlackKing => {
                        self.black_can_castle_kingside = false;
                        self.black_can_castle_queenside = false;
                    }
                    Piece::WhiteKing => {
                        self.white_can_castle_kingside = false;
                        self.white_can_castle_queenside = false;
                    }
                    Piece::BlackRook => {
                        if m == "a8" {
                            self.black_can_castle_queenside = false;
                        } else if m == "h8" {
                            self.black_can_castle_kingside = false;
                        }
                    }
                    Piece::WhiteRook => {
                        if m == "a1" {
                            self.white_can_castle_queenside = false;
                        } else if m == "h1" {
                            self.white_can_castle_kingside = false;
                        }
                    }
                    _ => {}
                }
                if self.squares[to_idx] != Piece::Empty {
                    self.half_move_clock = 0;
                }
                self.squares[to_idx] = self.squares[from_idx];
                self.squares[from_idx] = Piece::Empty;
            }
        }

        // Switch active colour, increment full move counter
        self.white_to_play = !self.white_to_play;
        if self.white_to_play {
            self.full_move += 1;
        }
        self.last_move = Some(m);
    }

    pub fn rank_file(coord: &str) -> (Rank, File) {
        let mut chars = coord.chars();
        let file = File::from_char(chars.next().unwrap());
        let rank = Rank::from_char(chars.next().unwrap());
        (rank, file)
    }

    pub fn rank_file_index(rank: Rank, file: File) -> usize {
        (rank as usize) * 8 + (file as usize)
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
