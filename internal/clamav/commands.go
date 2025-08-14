package clamav

type ClamCommand []byte

var (
	CmdPing     ClamCommand = []byte("nPING\n")
	CmdVersion  ClamCommand = []byte("nVERSION\n")
	CmdInstream ClamCommand = []byte("nINSTREAM\n")
)
