//go:build !windows

package boxdd

func knownProgramDataDir(name string) string {
	return `C:\ProgramData\` + name
}
