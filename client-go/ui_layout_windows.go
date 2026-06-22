//go:build windows

package main

const (
	vpnWindowWidth       = 430
	loginWindowHeight    = 560
	vpnBaseHeight        = 560
	vpnStatusTop         = 10
	vpnStatusHeight      = 34
	vpnPanelLeft         = 32
	vpnPanelRight        = 398
	vpnPanelTop          = 78
	vpnPanelInnerPad     = 20
	vpnRowTop            = 194
	vpnRowHeight         = 58
	vpnRowCardHeight     = 48
	vpnPanelBottomPad    = 24
	vpnRowLeft           = vpnPanelLeft + vpnPanelInnerPad
	vpnRowRight          = vpnPanelRight - vpnPanelInnerPad
	vpnRowButtonWidth    = 76
	vpnRowButtonX        = vpnRowRight - vpnRowButtonWidth - 6
	vpnTrafficGap        = 35
	vpnTrafficHeight     = 48
	vpnVersionGap        = 87
	vpnVersionHeight     = 34
	vpnWindowBottomExtra = 36
)

func currentVPNRowCount() int {
	count := visibleProfileCount()
	if count < 1 {
		return 1
	}
	return count
}

func vpnPanelBottom() int {
	return vpnRowTop + currentVPNRowCount()*vpnRowHeight + vpnPanelBottomPad
}

func vpnTrafficTop() int {
	return vpnPanelBottom() + vpnTrafficGap
}

func vpnVersionTop() int {
	return vpnTrafficTop() + vpnVersionGap
}

func vpnWindowHeight() int {
	height := vpnVersionTop() + vpnVersionHeight + vpnWindowBottomExtra
	if height < vpnBaseHeight {
		return vpnBaseHeight
	}
	return height
}
