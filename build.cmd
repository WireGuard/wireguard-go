@echo off

REM builds wireguard for windows

go get
go build -o wireguard-go.exe
