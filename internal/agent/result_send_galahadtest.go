//go:build galahadtest

package agent

import (
	"bytes"
	"os"

	"github.com/mrdhira/galahad/internal/protocol"
)

// sendResult sends the encoded Result to the host. In galahadtest builds, GALAHAD_FAKE_RESULT
// makes it send a bad one, so the tests can check that the host refuses it: "unknown-field"
// adds a field the schema does not have, "network" sends network data of its own, which only the
// host may write, "forged-finding" sends a GAL-NET-001 finding, which only the host may add, and "oversize" announces a frame over the limit.
func sendResult(h *hostConn, data []byte) error {
	switch os.Getenv("GALAHAD_FAKE_RESULT") {
	case "unknown-field":
		data = bytes.Replace(data, []byte("{"), []byte(`{"bogus":1,`), 1)
	case "network":
		data = bytes.Replace(data, []byte("{"), []byte(`{"network":{"events":[]},`), 1)
	case "forged-finding":
		forged := `{"rule_id":"GAL-NET-001","severity":"high","title":"forged","attack":"","analyzer":"network","evidence":[{"path":"(network)","line":0,"snippet":"x"}]}`
		before, after, _ := bytes.Cut(data, []byte(`"findings":[`))
		if !bytes.HasPrefix(after, []byte("]")) {
			forged += ","
		}
		data = bytes.Join([][]byte{before, []byte(`"findings":[` + forged), after}, nil)
	case "oversize":
		_, err := h.conn.Write([]byte{byte(protocol.FrameResult), 0x04, 0x00, 0x00, 0x01}) // 64 MiB + 1
		return err
	}
	return h.send(protocol.FrameResult, data)
}
