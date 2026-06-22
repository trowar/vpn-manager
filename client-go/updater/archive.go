package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func unzip(zipPath, targetDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	total := len(reader.File)
	if total == 0 {
		return fmt.Errorf("empty package")
	}
	updateDetail(fmt.Sprintf("准备解压 %d 个文件...", total))
	for index, item := range reader.File {
		cleanName := filepath.Clean(item.Name)
		if cleanName == "." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanName) {
			continue
		}
		targetPath := filepath.Join(targetDir, cleanName)
		if item.FileInfo().IsDir() {
			updateDetail(fmt.Sprintf("解压目录 %d/%d：%s", index+1, total, shortName(cleanName)))
			if err := os.MkdirAll(targetPath, item.Mode()); err != nil {
				return err
			}
			setProgress(68 + int((index+1)*16/total))
			continue
		}
		updateDetail(fmt.Sprintf("解压文件 %d/%d：%s", index+1, total, shortName(cleanName)))
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		src, err := item.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, item.Mode())
		if err != nil {
			_ = src.Close()
			return err
		}
		copyErr := copyZipEntry(dst, src, item.UncompressedSize64, index+1, total, cleanName)
		closeErr := dst.Close()
		_ = src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		setProgress(68 + int((index+1)*16/total))
	}
	updateDetail(fmt.Sprintf("解压完成：%d 个文件", total))
	return nil
}

func copyZipEntry(dst io.Writer, src io.Reader, totalBytes uint64, index, total int, name string) error {
	buf := make([]byte, 128*1024)
	var copied uint64
	lastDetailAt := time.Time{}
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
			copied += uint64(n)
			if time.Since(lastDetailAt) > 250*time.Millisecond || copied == totalBytes {
				if totalBytes > 0 {
					updateDetail(fmt.Sprintf(
						"解压文件 %d/%d：%s  %s/%s",
						index,
						total,
						shortName(name),
						formatBytes(int64(copied)),
						formatBytes(int64(totalBytes)),
					))
				} else {
					updateDetail(fmt.Sprintf(
						"解压文件 %d/%d：%s  %s",
						index,
						total,
						shortName(name),
						formatBytes(int64(copied)),
					))
				}
				lastDetailAt = time.Now()
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
