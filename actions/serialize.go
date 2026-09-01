package actions

import (
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// serializeTamperedPacket rebuilds a packet from its decoded layers. Stopping
// at the changed layer prevents a decoder-generated payload or failure layer
// from overwriting the layer's current payload.
//
// It deliberately serializes with empty SerializeOptions: recomputing lengths and checksums
// here would clobber fields that a tamper action intentionally corrupted, and would drop the
// intentionally malformed segments nested actions chain through. Instead, each tamper Apply
// hand-patches exactly the derived fields its target field can invalidate; see
// tcpAffectsIPLength and tcpFieldIsOption for that policy.
func serializeTamperedPacket(
	packet gopacket.Packet,
	tampered gopacket.Layer,
	stopAtTampered bool,
) (gopacket.Packet, error) {
	layers := packet.Layers()
	if len(layers) == 0 {
		return nil, errors.New("tampered packet has no parseable layers")
	}

	serializable := make([]gopacket.SerializableLayer, 0, len(layers)+1)
	found := false
	for _, layer := range layers {
		serializedLayer, ok := layer.(gopacket.SerializableLayer)
		if !ok {
			if !found {
				return nil, fmt.Errorf("layer %s is not serializable", layer.LayerType())
			}
			serializable = append(serializable, gopacket.Payload(layer.LayerContents()))
			break
		}
		serializable = append(serializable, serializedLayer)
		if layer == tampered {
			found = true
			if stopAtTampered {
				serializable = append(serializable, gopacket.Payload(layer.LayerPayload()))
				break
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("tampered layer %s is not in packet", tampered.LayerType())
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, serializable...); err != nil {
		return nil, err
	}

	// NoCopy: the serialize buffer was allocated here and is not reused, so the
	// packet may alias it instead of taking a second copy of every byte. Lazy:
	// the caller of a tampered packet usually just serializes it back out, so
	// eagerly re-decoding every layer is work for nobody.
	return gopacket.NewPacket(buffer.Bytes(), layers[0].LayerType(),
		gopacket.DecodeOptions{Lazy: true, NoCopy: true}), nil
}
