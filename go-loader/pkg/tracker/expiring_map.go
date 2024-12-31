package tracker

type ExpiringMap interface {
	// OnExpire is called when an entry expires.
	OnExpire(key ConnectionKey)
}
