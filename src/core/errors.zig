pub const ConfigError = error{
    MissingField,
    InvalidField,
    UnsupportedField,
    UnsupportedValue,
};

pub const ProtocolError = error{
    Truncated,
    InvalidAddressType,
    InvalidSocksVersion,
    InvalidSocksCommand,
    UnsupportedFragmentation,
    PacketTooLarge,
    ReplayDetected,
};
