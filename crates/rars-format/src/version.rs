#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFamily {
    Rar13,
    Rar15To40,
    Rar50Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveVersion {
    Rar13,
    Rar14,
    Rar15,
    Rar20,
    Rar29,
    Rar30,
    Rar40,
    Rar50,
    Rar70,
}

impl ArchiveVersion {
    pub const fn family(self) -> ArchiveFamily {
        match self {
            Self::Rar13 | Self::Rar14 => ArchiveFamily::Rar13,
            Self::Rar15 | Self::Rar20 | Self::Rar29 | Self::Rar30 | Self::Rar40 => {
                ArchiveFamily::Rar15To40
            }
            Self::Rar50 | Self::Rar70 => ArchiveFamily::Rar50Plus,
        }
    }

    pub const fn is_rar13_family(self) -> bool {
        matches!(self, Self::Rar13 | Self::Rar14)
    }
}
