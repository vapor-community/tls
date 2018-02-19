public indirect enum OpenSSLCipher {
    case not(OpenSSLCipher)
    case `default`
    case ecdh
    
    internal var string: String {
        switch self {
        case .not(let cipher):
            return "!\(cipher)"
        case .default: return "DEFAULT"
        case .ecdh: return "ECDH"
        }
    }
}
