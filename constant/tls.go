package constant

const ACMETLS1Protocol = "acme-tls/1"

// Values of tls.reality.key_share: the key exchange the REALITY ClientHello offers.
// Empty = what the uTLS fingerprint carries. From sing-box-lx (SPEC 089).
const (
	RealityKeyShareDefault   = ""
	RealityKeyShareHybrid    = "hybrid"
	RealityKeyShareClassical = "classical"
)

const (
	TLSEngineDefault = ""
	TLSEngineGo      = "go"
	TLSEngineApple   = "apple"
	TLSEngineWindows = "windows"
)
