//go:build with_gvisor

package tun

// nekoBufConfig is how the gVisor stack reads a packet from the TUN device on Android (neko): gVisor's own shape, views
// of 128 bytes up to 32 KiB, a packet taking only the ones its length needs. sing-tun reads each into one view of
// 65535 bytes, the size of the segments a Linux TUN device with a virtio header (GSO) gives; the phone's VPN device has
// no such header, and a packet then keeps the whole 64 KiB chunk while the stack holds it, its TCP receive window
// counting the bytes of the packet only. Four uploads through naive (a 128 KiB window each on the gvisor stack) kept
// 19.6 MB of those chunks in the background process's heap in Niko's e2e (CI 43702206651), some 2.2 KB of views for a
// packet of 1500 bytes in this shape. The views add up to 65664 bytes: any packet sing-tun's one view would take.
var nekoBufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}
