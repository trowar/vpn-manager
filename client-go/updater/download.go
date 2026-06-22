package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func downloadFile(downloadURL, targetPath string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	out, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer out.Close()
	total := resp.ContentLength
	var received int64
	startedAt := time.Now()
	lastDetailAt := time.Time{}
	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := out.Write(buf[:n]); err != nil {
				return err
			}
			received += int64(n)
			if total > 0 {
				percent := int(received * 100 / total)
				setProgress(5 + int(received*60/total))
				if time.Since(lastDetailAt) > 250*time.Millisecond || received == total {
					updateDetail(fmt.Sprintf(
						"%d%%  %s / %s  %s/s",
						percent,
						formatBytes(received),
						formatBytes(total),
						formatBytes(downloadSpeed(received, startedAt)),
					))
					lastDetailAt = time.Now()
				}
			} else if time.Since(lastDetailAt) > 250*time.Millisecond {
				updateDetail(fmt.Sprintf(
					"已下载 %s  %s/s",
					formatBytes(received),
					formatBytes(downloadSpeed(received, startedAt)),
				))
				lastDetailAt = time.Now()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	setProgress(68)
	if total > 0 {
		updateDetail(fmt.Sprintf("100%%  %s / %s", formatBytes(received), formatBytes(total)))
	} else {
		updateDetail(fmt.Sprintf("下载完成：%s", formatBytes(received)))
	}
	return nil
}
