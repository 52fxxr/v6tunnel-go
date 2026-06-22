//go:build !linux

package protocol

func setKeepAliveParams(fd int) {
	// 非 Linux 平台不设置高级 keepalive 参数
}
