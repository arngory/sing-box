//go:build windows

package boxdd

// niko: safe portable ZIP -> <ProgramFiles>\<Product> installation without EoP or TOCTOU (slice 14).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Staging directory is accessible ONLY to SYSTEM and Builtin Administrators (no AU read) until
// all manifest and Authenticode checks pass; AU RX is applied right before atomic promotion.
const (
	stagingDirectorySDDL   = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	installedDirectorySDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;AU)"
	installedFileSDDL      = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;AU)"
)

type stagedInstallation struct {
	daemonPath            string
	targetRoot            string
	backupRoot            string
	suffix                string
	swapped               bool
	stoppedRunningService bool
	committed             bool
}

func (s *stagedInstallation) Commit() {
	if s == nil || s.committed {
		return
	}
	s.committed = true
	if s.backupRoot != "" {
		_ = os.RemoveAll(s.backupRoot)
		s.backupRoot = ""
	}
}

func (s *stagedInstallation) Rollback() {
	if s == nil || s.committed || !s.swapped {
		return
	}
	s.committed = true
	if s.backupRoot != "" {
		_, _ = stopInstalledServiceIfRunning()
		failedRoot := fmt.Sprintf("%s.failed-%s", s.targetRoot, s.suffix)
		if err := moveDirectoryWindows(s.targetRoot, failedRoot); err == nil {
			if err := moveDirectoryWindows(s.backupRoot, s.targetRoot); err == nil {
				_ = os.RemoveAll(failedRoot)
			}
		}
		if s.stoppedRunningService {
			_ = startInstalledServiceIfPresent()
		}
	} else {
		_ = os.RemoveAll(s.targetRoot)
	}
}

// stageAndInstallToProgramFiles copies a portable installation from a user-writable directory
// into a SYSTEM/BA-only staging directory inside <ProgramFiles> using handle-relative NtCreateFile
// opens (no reparse-point traversal, no hardlinks, no ADS/MOTW), verifies the embedded manifest
// SHA-256 and every file hash while copying, copies the daemon binary directly from its own
// already-verified locked handle, verifies Authenticode signers in staging, and atomically swaps
// it into <ProgramFiles>\<Product>.
func stageAndInstallToProgramFiles(executablePath string, allowUnsafe bool) (*stagedInstallation, error) {
	programFilesDir, err := knownProgramFilesDir()
	if err != nil {
		return nil, err
	}
	return stageAndInstallIntoRoot(executablePath, programFilesDir, allowUnsafe)
}

func stageAndInstallIntoRoot(executablePath string, installParentDir string, allowUnsafe bool) (*stagedInstallation, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, &installExitError{
			code: InstallExitNotElevated,
			err:  E.New("installing the service requires an elevated process"),
		}
	}
	if activeOptions.InstallManifestSHA256 == "" {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.New("install manifest SHA-256 is required for Program Files installation"),
		}
	}
	expectedManifestSum, err := hex.DecodeString(activeOptions.InstallManifestSHA256)
	if err != nil || len(expectedManifestSum) != sha256.Size {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.New("invalid embedded install manifest SHA-256"),
		}
	}

	selfHandle, err := openLockedExecutable(executablePath)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitInvalidLayout,
			err:  E.Cause(err, "open daemon executable"),
		}
	}
	defer windows.CloseHandle(selfHandle)

	daemonFinalPath, err := finalWindowsPath(selfHandle)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitInvalidLayout,
			err:  E.Cause(err, "resolve daemon executable path"),
		}
	}
	srcRoot, _, err := installedApplicationPath(daemonFinalPath)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitInvalidLayout,
			err:  err,
		}
	}

	cleanParent := filepath.Clean(installParentDir)
	if !allowUnsafe {
		volumeRoot, err := validateFixedNTFSVolume(cleanParent)
		if err != nil {
			return nil, err
		}
		if err := validateInstallationAncestors(cleanParent, volumeRoot, false); err != nil {
			return nil, err
		}
	}

	targetRoot := filepath.Join(cleanParent, activeNames.Product)
	if sameInstallRoot(srcRoot, targetRoot) {
		return &stagedInstallation{daemonPath: daemonFinalPath, targetRoot: targetRoot}, nil
	}

	mySigner, err := authenticodeSigner(daemonFinalPath, selfHandle)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitSignatureFailed,
			err:  E.Cause(err, "authenticate running daemon executable"),
		}
	}

	// Open srcRoot without following reparse points and without FILE_SHARE_DELETE so it cannot be
	// renamed/swapped while we traverse relative to this handle.
	srcRootHandle, err := openDirNoFollowNoDelete(srcRoot)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitInvalidSource,
			err:  E.Cause(err, "open source installation directory"),
		}
	}
	defer windows.CloseHandle(srcRootHandle)

	var nonce [8]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, E.Cause(err, "generate staging directory suffix")
	}
	suffix := hex.EncodeToString(nonce[:])
	stagingRoot := filepath.Join(cleanParent, fmt.Sprintf("%s.staging-%s", activeNames.Product, suffix))

	if err := createProtectedInstallDir(stagingRoot); err != nil {
		return nil, E.Cause(err, "create protected staging directory")
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(stagingRoot)
		}
	}()

	// 1. Read and verify resources/files.sha256 strictly via handle-relative NtCreateFile opens.
	manifestHandle, err := openRelativeFileNoFollow(srcRootHandle, installManifestRelativePath)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.Cause(err, "open install manifest"),
		}
	}
	manifestData, err := readHandleBounded(manifestHandle, maxInstallManifestSize)
	_ = windows.CloseHandle(manifestHandle)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.Cause(err, "read install manifest"),
		}
	}
	actualManifestSum := sha256.Sum256(manifestData)
	if subtle.ConstantTimeCompare(actualManifestSum[:], expectedManifestSum) != 1 {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.New("install manifest SHA-256 mismatch"),
		}
	}
	entries, err := parseInstallManifest(manifestData, activeNames.DaemonExe)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  err,
		}
	}

	appKey := strings.ToLower(activeNames.ApplicationExe)
	hasAppEntry := false
	for _, entry := range entries {
		if entry.relKey == appKey {
			hasAppEntry = true
			break
		}
	}
	if !hasAppEntry {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.New("install manifest does not list ", activeNames.ApplicationExe),
		}
	}

	if err := writeFileSynced(filepath.Join(stagingRoot, filepath.FromSlash(installManifestRelativePath)), manifestData); err != nil {
		return nil, E.Cause(err, "stage install manifest")
	}

	// 2. Copy ONLY the files listed in the verified manifest via handle-relative opens (zero TOCTOU,
	// strips ADS/MOTW/ACLs, refuses reparse points and hardlinks, hashes while copying, enforces size cap).
	var totalCopied int64 = int64(len(manifestData))
	for _, entry := range entries {
		fileHandle, openErr := openRelativeFileNoFollow(srcRootHandle, entry.relSlash)
		if openErr != nil {
			code := InstallExitInvalidSource
			if errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) || errors.Is(openErr, windows.ERROR_PATH_NOT_FOUND) {
				code = InstallExitManifestFailed
			}
			return nil, &installExitError{
				code: code,
				err:  E.Cause(openErr, "open source file ", entry.relSlash),
			}
		}
		dstPath := filepath.Join(stagingRoot, filepath.FromSlash(entry.relSlash))
		copied, sum, copyErr := copyHandleWithSHA256(fileHandle, dstPath, maxInstallTotalBytes-totalCopied)
		_ = windows.CloseHandle(fileHandle)
		if copyErr != nil {
			return nil, &installExitError{
				code: InstallExitInvalidSource,
				err:  E.Cause(copyErr, "stage file ", entry.relSlash),
			}
		}
		totalCopied += copied
		if subtle.ConstantTimeCompare(sum[:], entry.sum) != 1 {
			return nil, &installExitError{
				code: InstallExitManifestFailed,
				err:  E.New("SHA-256 mismatch for staged file: ", entry.relSlash),
			}
		}
	}

	// 3. Copy the running daemon executable directly from selfHandle (already locked and Authenticode-verified)
	// so no downgrade or path substitution is possible for the daemon binary itself.
	stagedDaemonPath := filepath.Join(stagingRoot, "resources", "daemon", activeNames.DaemonExe)
	if _, err := windows.Seek(selfHandle, 0, io.SeekStart); err != nil {
		return nil, E.Cause(err, "seek running daemon executable")
	}
	copiedDaemon, selfSum, err := copyHandleWithSHA256(selfHandle, stagedDaemonPath, maxInstallTotalBytes-totalCopied)
	if err != nil {
		return nil, E.Cause(err, "stage daemon executable")
	}
	totalCopied += copiedDaemon

	// 4. Verify Authenticode signers of both staged executables inside the SY/BA-only staging directory.
	if err := verifyStagedExecutableSigner(stagedDaemonPath, mySigner); err != nil {
		return nil, &installExitError{
			code: InstallExitSignatureFailed,
			err:  E.Cause(err, "verify staged daemon signature"),
		}
	}
	stagedDaemonDiskSum, err := sha256File(stagedDaemonPath)
	if err != nil || subtle.ConstantTimeCompare(stagedDaemonDiskSum[:], selfSum[:]) != 1 {
		return nil, &installExitError{
			code: InstallExitManifestFailed,
			err:  E.New("staged daemon executable content mismatch"),
		}
	}
	stagedAppPath := filepath.Join(stagingRoot, activeNames.ApplicationExe)
	if err := verifyStagedExecutableSigner(stagedAppPath, mySigner); err != nil {
		return nil, &installExitError{
			code: InstallExitSignatureFailed,
			err:  E.Cause(err, "verify staged application signature"),
		}
	}

	// 5. All manifest hashes and Authenticode signatures are verified: grant AU read/execute on the
	// verified staging tree right before atomic promotion (so targetRoot has final ACLs even when
	// --allow-unsafe-installation-directory-permissions skips secureWindowsInstallation's ACL pass).
	if err := applyProtectedTree(stagingRoot, installedDirectorySDDL, installedFileSDDL); err != nil {
		return nil, E.Cause(err, "apply final permissions to verified staging directory")
	}

	// 6. Promote stagingRoot -> targetRoot atomically, restarting any existing service on failure.
	targetExists, err := checkTargetInstallDir(targetRoot)
	if err != nil {
		return nil, &installExitError{
			code: InstallExitInvalidSource,
			err:  err,
		}
	}
	var backupRoot string
	var stoppedRunning bool
	if targetExists {
		stoppedRunning, err = stopInstalledServiceIfRunning()
		if err != nil {
			return nil, E.Cause(err, "stop running service before update")
		}
		backupRoot = filepath.Join(cleanParent, fmt.Sprintf("%s.old-%s", activeNames.Product, suffix))
		if err := moveDirectoryWindows(targetRoot, backupRoot); err != nil {
			if stoppedRunning {
				_ = startInstalledServiceIfPresent()
			}
			if isTargetBusyError(err) {
				return nil, &installExitError{
					code: InstallExitTargetBusy,
					err:  E.Cause(err, "existing installation directory is in use; close ", activeNames.Product, " and retry"),
				}
			}
			return nil, E.Cause(err, "move existing installation aside")
		}
	}

	if err := moveDirectoryWindows(stagingRoot, targetRoot); err != nil {
		if backupRoot != "" {
			_ = moveDirectoryWindows(backupRoot, targetRoot)
		}
		if stoppedRunning {
			_ = startInstalledServiceIfPresent()
		}
		if isTargetBusyError(err) {
			return nil, &installExitError{
				code: InstallExitTargetBusy,
				err:  E.Cause(err, "promote staged installation"),
			}
		}
		return nil, E.Cause(err, "promote staged installation")
	}
	keepStaging = true

	return &stagedInstallation{
		daemonPath:            filepath.Join(targetRoot, "resources", "daemon", activeNames.DaemonExe),
		targetRoot:            targetRoot,
		backupRoot:            backupRoot,
		suffix:                suffix,
		swapped:               true,
		stoppedRunningService: stoppedRunning,
	}, nil
}

func sameInstallRoot(srcRoot, targetRoot string) bool {
	if strings.EqualFold(filepath.Clean(srcRoot), filepath.Clean(targetRoot)) {
		return true
	}
	handle, err := openNoFollowWindows(targetRoot, windows.READ_CONTROL)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	targetFinal, err := finalWindowsPath(handle)
	if err != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(srcRoot), filepath.Clean(targetFinal))
}

func createProtectedInstallDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString(stagingDirectorySDDL)
	if err != nil {
		return err
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	return winio.RunWithPrivilege(winio.SeRestorePrivilege, func() error {
		if err := windows.CreateDirectory(pathPtr, sa); err != nil {
			return err
		}
		return applyProtectedFileSecurity(path, sd)
	})
}

func openDirNoFollowNoDelete(dirPath string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(dirPath)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // no FILE_SHARE_DELETE
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return 0, E.New("directory is a reparse point: ", dirPath)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = windows.CloseHandle(handle)
		return 0, E.New("path is not a directory: ", dirPath)
	}
	return handle, nil
}

// openRelativeFileNoFollow walks relSlash component-by-component strictly relative to rootHandle
// using NtCreateFile(RootDirectory, FILE_OPEN_REPARSE_POINT). Every intermediate directory is
// verified to be a non-reparse directory and held without FILE_SHARE_DELETE until its child opens;
// the final leaf is verified to be a non-reparse regular file with NumberOfLinks == 1.
func openRelativeFileNoFollow(rootHandle windows.Handle, relSlash string) (windows.Handle, error) {
	parts := strings.Split(relSlash, "/")
	if len(parts) == 0 {
		return 0, E.New("empty relative path")
	}

	curDir := rootHandle
	var openedDirs []windows.Handle
	defer func() {
		for i := len(openedDirs) - 1; i >= 0; i-- {
			_ = windows.CloseHandle(openedDirs[i])
		}
	}()

	for i := 0; i < len(parts)-1; i++ {
		nextDir, err := ntOpenChildNoFollow(curDir, parts[i], true)
		if err != nil {
			return 0, err
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(nextDir, &info); err != nil {
			_ = windows.CloseHandle(nextDir)
			return 0, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			_ = windows.CloseHandle(nextDir)
			return 0, E.New("source subdirectory is a reparse point: ", parts[i])
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			_ = windows.CloseHandle(nextDir)
			return 0, E.New("source path component is not a directory: ", parts[i])
		}
		openedDirs = append(openedDirs, nextDir)
		curDir = nextDir
	}

	leafName := parts[len(parts)-1]
	fileHandle, err := ntOpenChildNoFollow(curDir, leafName, false)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(fileHandle, &info); err != nil {
		_ = windows.CloseHandle(fileHandle)
		return 0, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(fileHandle)
		return 0, E.New("source file is a reparse point: ", relSlash)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(fileHandle)
		return 0, E.New("source file is a directory: ", relSlash)
	}
	if info.NumberOfLinks > 1 {
		_ = windows.CloseHandle(fileHandle)
		return 0, E.New("source file is hard-linked: ", relSlash)
	}
	return fileHandle, nil
}

func ntOpenChildNoFollow(parentDir windows.Handle, childName string, isDir bool) (windows.Handle, error) {
	ntName, err := windows.NewNTUnicodeString(childName)
	if err != nil {
		return 0, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parentDir,
		ObjectName:    ntName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	var (
		handle       windows.Handle
		iosb         windows.IO_STATUS_BLOCK
		desired      uint32 = windows.FILE_GENERIC_READ | windows.SYNCHRONIZE
		shareAccess  uint32 = windows.FILE_SHARE_READ
		createOption uint32 = windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT
	)
	if isDir {
		shareAccess = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE // no FILE_SHARE_DELETE
		createOption |= windows.FILE_DIRECTORY_FILE
	} else {
		createOption |= windows.FILE_NON_DIRECTORY_FILE
	}
	err = windows.NtCreateFile(
		&handle,
		desired,
		oa,
		&iosb,
		nil,
		0,
		shareAccess,
		windows.FILE_OPEN,
		createOption,
		0,
		0,
	)
	if err != nil {
		if ntStatus, ok := err.(windows.NTStatus); ok {
			return 0, ntStatus.Errno()
		}
		return 0, err
	}
	return handle, nil
}

func readHandleBounded(handle windows.Handle, limit int64) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 32*1024)
	for {
		var n uint32
		err := windows.ReadFile(handle, buf, &n, nil)
		if n > 0 {
			if int64(out.Len())+int64(n) > limit {
				return nil, E.New("file exceeds maximum allowed size")
			}
			out.Write(buf[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return nil, err
		}
		if n == 0 {
			break
		}
	}
	return out.Bytes(), nil
}

func copyHandleWithSHA256(srcHandle windows.Handle, dstPath string, maxBytes int64) (int64, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if maxBytes < 0 {
		return 0, zero, E.New("staged installation exceeds size limit")
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return 0, zero, err
	}
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, zero, err
	}
	hasher := sha256.New()
	buf := make([]byte, 64*1024)
	var total int64
	for {
		var n uint32
		readErr := windows.ReadFile(srcHandle, buf, &n, nil)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				_ = dst.Close()
				return 0, zero, E.New("staged installation exceeds size limit")
			}
			chunk := buf[:n]
			if _, err := dst.Write(chunk); err != nil {
				_ = dst.Close()
				return 0, zero, err
			}
			_, _ = hasher.Write(chunk)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, windows.ERROR_HANDLE_EOF) {
				break
			}
			_ = dst.Close()
			return 0, zero, readErr
		}
		if n == 0 {
			break
		}
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return 0, zero, err
	}
	if err := dst.Close(); err != nil {
		return 0, zero, err
	}
	var sum [sha256.Size]byte
	hasher.Sum(sum[:0])
	return total, sum, nil
}

func writeFileSynced(dstPath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := dst.Write(data); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

func verifyStagedExecutableSigner(path string, expectedSigner []byte) error {
	handle, err := openLockedExecutable(path)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	finalPath, err := finalWindowsPath(handle)
	if err != nil {
		return err
	}
	signer, err := authenticodeSigner(finalPath, handle)
	if err != nil {
		return err
	}
	if !bytes.Equal(signer, expectedSigner) {
		return E.New("staged executable has a different signing certificate: ", filepath.Base(path))
	}
	return nil
}

func checkTargetInstallDir(targetRoot string) (bool, error) {
	handle, err := openNoFollowWindows(targetRoot, windows.READ_CONTROL)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return false, nil
		}
		return false, E.Cause(err, "inspect target installation directory")
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, E.Cause(err, "stat target installation directory")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, E.New("target installation directory is a reparse point")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false, E.New("target installation path is not a directory")
	}
	return true, nil
}

func stopInstalledServiceIfRunning() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(activeNames.Service)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, err
	}
	defer service.Close()
	st, err := service.Query()
	if err != nil {
		return false, err
	}
	wasRunning := st.State != svc.Stopped
	if !wasRunning {
		return false, nil
	}
	if err := stopServiceAndWait(service); err != nil {
		return false, err
	}
	return true, nil
}

func startInstalledServiceIfPresent() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(activeNames.Service)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer service.Close()
	return startServiceAndWait(service)
}

func moveDirectoryWindows(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_WRITE_THROUGH)
}

func isTargetBusyError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
