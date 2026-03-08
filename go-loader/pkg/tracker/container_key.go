package tracker

import "hash/fnv"

func ContainerKeyHash(id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return h.Sum64()
}
