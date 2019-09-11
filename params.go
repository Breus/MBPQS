package mbpqs

/*
 The MBPQS parameters, n and w are passed to wotsp.
*/
type Params struct {
	n         uint32 // the security parameter, length of message digest and three nodes in bytes.
	w         uint16 // the Winternitz parameter, used in WOTS-T.
	rootH     uint32 // the height of the three (# levels -1).
	initChanH uint32 // the inital chain tree height.
	d         uint32 // the chain tree height growing exponent.
}
