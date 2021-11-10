# Project: ngdlp
# Date:	2021.05.26
# Author: <empty>
# Description: Makefile for the whole project
# 	

PROJECT_NAME ?= ngdlp
OUTPUT ?= ./output
FLAGS := -gcflags=all="-N -l"
ifeq ($(OS),Windows_NT)
	OS := windows
	EXT_NAME := exe
else
	ifeq ($(shell uname), Darwin)
		OS := darwin
		EXT_NAME := mac
	else
		OS := linux
		EXT_NAME := elf
	endif
endif

.PHONY: all dep build clean test coverage coverhtml lint bench
all: build

dep:
	@go get -v -d .
	@go install github.com/kevinburke/go-bindata@latest
	@go install golang.org/x/lint@latest
	@go install golang.org/x/perf/cmd/benchstat@latest
	@go install github.com/uber/go-torch@latest
	@go install github.com/go-delve/delve/cmd/dlv@latest

lint:
	@$(GOPATH)/bin/golint ./...

gen: clean
	@go generate

release:
	@mkdir -p $(OUTPUT)
	@GOOS=linux go build $(FLAGS) -o $(OUTPUT)/ngdlp.elf ./mainrun/
	@GOOS=darwin go build $(FLAGS) -o $(OUTPUT)/ngdlp.mac ./mainrun/
	@GOOS=windows go build $(FLAGS) -o $(OUTPUT)/ngdlp.exe ./mainrun/

build: gen release
	
run: build
	@go run $(FLAGS) ./mainrun/

clean:
	@rm -rf ./output

test: 
	@go test -v -failfast  -count=1 -timeout 10s

bench: 
	@go test -bench=. -benchtime=3s -benchmem 

perf:
	@go test -bench=BenchmarkEngine_Deidentify10k -benchtime=2x -benchmem -cpuprofile=./bench/cpu.out -memprofile=./bench/mem.out -trace=./bench/trace.out
	@go-torch -b ./bench/cpu.out -f ./bench/torch.svg
