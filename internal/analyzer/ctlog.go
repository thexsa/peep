package analyzer

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// CTLogResult holds the result of a Certificate Transparency check.
type CTLogResult struct {
	Found       bool       `json:"found"`
	SCTs        []SCTEntry `json:"scts,omitempty"`
	Error       string     `json:"error,omitempty"`
	IsPrivateCA bool       `json:"is_private_ca"`
}

// SCTEntry represents a single Signed Certificate Timestamp embedded in a cert.
type SCTEntry struct {
	LogID     string    `json:"log_id"`
	LogName   string    `json:"log_name"`
	Timestamp time.Time `json:"timestamp"`
	Version   uint8     `json:"version"`
}

// sctExtensionOID is the OID for the SCT List extension (1.3.6.1.4.1.11129.2.4.2).
var sctExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// CheckCTLogs parses the Signed Certificate Timestamps (SCTs) embedded in the
// certificate. SCTs are cryptographic proof that the cert was submitted to
// Certificate Transparency logs before issuance.
//
// This requires no network calls — the proof is in the cert itself.
func CheckCTLogs(cert *x509.Certificate, trustStoreVerified bool) CTLogResult {
	result := CTLogResult{}

	if cert == nil {
		result.Error = "no certificate provided"
		return result
	}

	// Private CA: internal CAs don't submit to CT logs
	if !trustStoreVerified {
		result.IsPrivateCA = true
		return result
	}

	// Find the SCT extension
	var sctBytes []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sctExtensionOID) {
			sctBytes = ext.Value
			break
		}
	}

	if sctBytes == nil {
		result.Found = false
		return result
	}

	// The extension value is DER-encoded: an OCTET STRING wrapping the TLS-encoded SCT list
	var rawSCTList []byte
	if _, err := asn1.Unmarshal(sctBytes, &rawSCTList); err != nil {
		// Some certs have the TLS-encoded list directly without the OCTET STRING wrapper
		rawSCTList = sctBytes
	}

	scts, err := parseSCTList(rawSCTList)
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse SCT list: %s", err)
		return result
	}

	if len(scts) == 0 {
		result.Found = false
		return result
	}

	result.Found = true
	result.SCTs = scts
	return result
}

// parseSCTList parses a TLS-encoded SignedCertificateTimestampList.
// Format:
//
//	uint16 list_length
//	  repeated:
//	    uint16 sct_length
//	    opaque sct_data[sct_length]
func parseSCTList(data []byte) ([]SCTEntry, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("SCT list too short (%d bytes)", len(data))
	}

	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return nil, fmt.Errorf("SCT list length mismatch: header says %d, have %d", listLen, len(data))
	}
	data = data[:listLen]

	var scts []SCTEntry
	for len(data) > 0 {
		if len(data) < 2 {
			break
		}
		sctLen := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if len(data) < sctLen {
			break
		}

		sct, err := parseSCT(data[:sctLen])
		if err == nil {
			scts = append(scts, sct)
		}
		data = data[sctLen:]
	}

	return scts, nil
}

// parseSCT parses a single Signed Certificate Timestamp.
// Format:
//
//	uint8  version (0 = v1)
//	opaque log_id[32]
//	uint64 timestamp (ms since epoch)
//	uint16 extensions_length
//	opaque extensions[extensions_length]
//	uint8  hash_algorithm
//	uint8  signature_algorithm
//	uint16 signature_length
//	opaque signature[signature_length]
func parseSCT(data []byte) (SCTEntry, error) {
	// Minimum: 1 (version) + 32 (log_id) + 8 (timestamp) + 2 (ext_len) = 43
	if len(data) < 43 {
		return SCTEntry{}, fmt.Errorf("SCT too short (%d bytes)", len(data))
	}

	entry := SCTEntry{
		Version: data[0],
		LogID:   hex.EncodeToString(data[1:33]),
	}

	// Timestamp: milliseconds since Unix epoch
	tsMs := binary.BigEndian.Uint64(data[33:41])
	entry.Timestamp = time.Unix(int64(tsMs/1000), int64(tsMs%1000)*int64(time.Millisecond))

	// Look up the log name
	entry.LogName = knownCTLogs[entry.LogID]

	return entry, nil
}

// knownCTLogs maps log IDs (hex-encoded SHA-256 of public key) to human-readable names.
// Source: https://www.gstatic.com/ct/log_list/v3/log_list.json
var knownCTLogs = map[string]string{
	// Google
	"0e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e21": "Google Argon 2026h1",
	"d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c56977": "Google Argon 2026h2",
	"d6d58da9d01753f36a4aa0c7574902afebc7dc2cd38cd9f764c80c89191e9f02": "Google Argon 2027h1",
	"969764bf555897adf743876837084277e9f03ad5f6a4f3366e46a43f0fcaa9c6": "Google Xenon 2026h1",
	"d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14": "Google Xenon 2026h2",
	"44c2bd0ce9140e64a5c94a01930a5aa1bb35970e00ee111689682a1c44d7b566": "Google Xenon 2027h1",

	// Cloudflare
	"cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e7": "Cloudflare Nimbus 2026",
	"4c63dc98e59c1dab88f61e8a3ddeae8fab44a3377b5f9b94c3fba19cfcc1be26": "Cloudflare Nimbus 2027",

	// DigiCert
	"6411c46ca412eca7891ca2022e00bcab4f2807d41e3527abeafed503c97dcdf0": "DigiCert Wyvern 2026h1",
	"c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd": "DigiCert Wyvern 2026h2",
	"001a5d1a1c2d9375b6485578f82f71a1ae6eef397d297c8ae3157bcadee1a01e": "DigiCert Wyvern 2027h1",
	"37aa07cc216f2e6d919c709d24d8f731b00f2b147c621cc091a5fa1a84d816dd": "DigiCert Wyvern 2027h2",
	"499c9b69de1d7cecfc36decd8764a6b85baf0a878019d15552fbe9eb29ddf8c3": "DigiCert Sphinx 2026h1",
	"944e4387faecc1ef81f3192426a8186501c7d35f3802013f72677d55372e19d8": "DigiCert Sphinx 2026h2",
	"46a23967c60db64687c66f3df999947693a6a611208457d555e7e3d0a1d9b646": "DigiCert Sphinx 2027h1",
	"1fb0f8a92d8adda121776c05e2aa2e15bacbc62b65393695576aaab52e11d11d": "DigiCert Sphinx 2027h2",

	// Sectigo
	"252f94c22b29e96e9f411a72072b695c5b52ff97a90d2540bbfcdc51ec4dee0b": "Sectigo Mammoth 2026h1",
	"94b1c18ab0d057c47be0ac040e1f2cbc8dc375727bc951f20a526126863ba73c": "Sectigo Mammoth 2026h2",
	"566cd5a376be83dfe342b675c49c232498a769bac382cbab49a3877d9ab32d01": "Sectigo Sabre 2026h1",
	"1f56d1ab94704a41dd3feafdf4699355302c1431bfe61346089fffae795dcc2f": "Sectigo Sabre 2026h2",
	"d16ea9a568077e6635a03f37a5ddbc03a53c411214d48818f5e931b323cb9504": "Sectigo Elephant 2026h1",
	"af67883b57b04edd8fa6d97ef62ea8eb810ac77160f0245e55d60c2fe785873a": "Sectigo Elephant 2026h2",
	"604c9aaf7a7f775f01d406fc920dc899eb0b1c7df8c9521bfafa17773b978bc9": "Sectigo Elephant 2027h1",
	"a2490cdcdb8e33a400321760d6d4d51a2036191ea77d968be26a8a00f6fffff7": "Sectigo Elephant 2027h2",
	"16832dabf0a9250f0ff03aa545ffc8bfc823d0874bf6042927f8e71f3313f5fa": "Sectigo Tiger 2026h1",
	"c8a3c47fc7b3adb9356b013f6a7a126de33a4e43a5c646f997ad3975991dcf9a": "Sectigo Tiger 2026h2",
	"1c9f682ce9faf0456950f81b968a87dddb3210d84ce6c8b2e382524ac4cf599f": "Sectigo Tiger 2027h1",
	"03802ac262f6e05e03f8bc6f7b9851324fd76a3df5b7595175e222fb8e9bd5f6": "Sectigo Tiger 2027h2",

	// Let's Encrypt
	"1986d4c728aa6ffeba036f782a4d0191aace2d72310faece5d70412d254cc7d4": "Let's Encrypt Oak 2026h1",
	"acab30706cebec8431f413d2f4915f111e422443b1f2a68c4f3c2b3ba71e02c3": "Let's Encrypt Oak 2026h2",

	// TrustAsia
	"74db9d58f7d47e9dfd787a162a991c18cf698da7c729918c9a18b0450dba44bc": "TrustAsia Log 2026a",
	"25b7efdea1130193ed93079770aa322a26620de35ac8aa7c75197de0b1a9e065": "TrustAsia Log 2026b",
	"eddaeb815c63213449b47be5077905abd0d93147c27ac5146b3bc58e43e9b6c7": "TrustAsia HETU 2027",

	// Historical logs (2024-2025) — still seen in unexpired certs
	"eecdd064d5db1acec55cb79db4cd13a2320c36ca2be9b8f0c58f03390986b4e8": "Google Argon 2025h1",
	"12f14e34bd53724c84045c2a4047b2af25fbe2c8dbb30db18e6e15dc683e0540": "Google Argon 2025h2",
	"a2e30ee4f9f4c23a0b149e73532e2f1cd5ab3d0f2178afa50dbe952a2a7a1ca0": "Google Xenon 2025h1",
	"cf119ce2e93eb2cb1e6b18fcb77b69f3ebce96d2e2cb76e7e6f71e754e601b5c": "Google Xenon 2025h2",
	"a12c9c344bd0e9ec8b8a2bc2341407227b26acd48b9ca5d036e6bdc502ef3b43": "Cloudflare Nimbus 2025",
	"7362091ef64bff4f1a30cdcdb2b0a4d36ce8e3a3b95caa34ad3f29ecbabfa000": "DigiCert Nessie 2025",
	"733482aa24ef7b4de6cf803ca2fc20e38e62218ddc6f71ed65abae4c20f278c2": "DigiCert Yeti 2025",
	"b6d773ee8d9358f82d60c4d2dc2e4b6de67bed9f1e2c5614ae04c9a94cc9e99f": "Sectigo Mammoth 2025h1",
	"e710f04ece7e19a706e1b0a0a2572ef62ce8f429a1ec3496a3f0e90fddafeee9": "Sectigo Sabre 2025h1",
}
